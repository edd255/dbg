#include "../include/debugger.hpp"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <print>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "../libs/linenoise/linenoise.h"

namespace dbg {
    namespace {
        template <class... Ts>
        struct overloaded : Ts... {
            using Ts::operator()...;
        };

        template <class... Ts>
        overloaded(Ts...) -> overloaded<Ts...>;

        [[nodiscard]] 
        const char* signal_name(int signal_number) {
            return strsignal(signal_number);
        }
    }

    Debugger::Debugger(std::string program_name, pid_t process_id)
        : m_program_name{std::move(program_name)},
          m_tracee{process_id},
          m_debug_info{m_program_name}
    {}

    Debugger::~Debugger() noexcept {
        if (m_process_state != StopReason::stopped) {
            return;
        }

        for (auto& [address, breakpoint] : m_breakpoints) {
            try {
                if (breakpoint.is_enabled()) {
                    breakpoint.disable();
                }
            } catch (...) {
            }
        }
    }

    void Debugger::run() {
        wait_for_signal();
        if (m_process_state != StopReason::stopped) {
            return;
        }
        initialise_load_address();
        using LinePtr = std::unique_ptr<char, decltype(&linenoiseFree)>;
        while (!m_should_exit) {
            LinePtr line{linenoise("> "), linenoiseFree};
            if (!line) {
                break;
            }
            try {
                auto command = parse_command(line.get());
                if (!command) {
                    std::println(stderr, "{}", command.error().message);
                } else {
                    execute(*command);
                }
            } catch (const std::exception& e) {
                std::println(stderr, "{}", e.what());
            }
            linenoiseHistoryAdd(line.get());
        }
    }

    void Debugger::execute(const Command& command) {
        std::visit(
                overloaded{
                        [] (const NoopCommand&) {},
                        [this] (const ContinueCommand&) { continue_execution(); },
                        [this] (const BreakAddressCommand& cmd) { set_breakpoint_at_address(cmd.address); },
                        [this] (const BreakSourceCommand& cmd) { set_breakpoint_at_source_line(cmd.file, cmd.line); },
                        [this] (const BreakFunctionCommand& cmd) { set_breakpoint_at_function(cmd.name); },
                        [this] (const RegisterDumpCommand&) { dump_registers(); },
                        [this] (const RegisterReadCommand& cmd) {
                            std::println("0x{:x}", m_tracee.read_register(cmd.reg));
                        },
                        [this] (const RegisterWriteCommand& cmd) {
                            m_tracee.write_register(cmd.reg, cmd.value);
                        },
                        [this] (const MemoryReadCommand& cmd) {
                            std::println("{:x}", m_tracee.read_word(cmd.address));
                        },
                        [this] (const MemoryWriteCommand& cmd) {
                            m_tracee.write_word(cmd.address, cmd.value);
                        },
                        [this] (const ExitCommand&) { m_should_exit = true; },
                        [this] (const StepInstructionCommand&) {
                            single_step_instruction_with_breakpoint_check();
                            print_source_from_program_counter(m_tracee.program_counter());
                        },
                        [this] (const StepInCommand&) { step_in(); },
                        [this] (const StepOverCommand&) { step_over(); },
                        [this] (const StepOutCommand&) { step_out(); },
                        [this] (const SymbolCommand& cmd) {
                            for (const auto& symbol : m_debug_info.lookup_symbol(cmd.name)) {
                                std::println(
                                        "{} {} 0x{:x}",
                                        symbol.name,
                                        symbol_to_string(symbol.type),
                                        symbol.address
                                );
                            }
                        },
                        [this] (const BacktraceCommand&) { print_backtrace(); },
                        [this] (const VariablesCommand&) { read_variables(); },
                },
                command
        );
    }

    void Debugger::continue_execution() {
        if (m_process_state != StopReason::stopped) {
            std::println(stderr, "Process is not running");
            return;
        }

        step_over_breakpoint();
        m_tracee.resume();
        wait_for_signal();
    }

    void Debugger::set_breakpoint_at_address(RuntimeAddress address) {
        std::println("Set breakpoint at address 0x{:x}", address.value);

        auto [it, inserted] = m_breakpoints.try_emplace(address, m_tracee, address);
        if (!it->second.is_enabled()) {
            it->second.enable();
        }
    }

    void Debugger::dump_registers() const {
        auto regs = m_tracee.registers();

        for (const auto& descriptor : descriptors) {
            auto tab = descriptor.name == "orig_rax" ? " " : "\t ";
            std::println("{}{} 0x{:016x}", descriptor.name, tab, read_register_value(regs, descriptor.reg));
        }
    }

    StopInfo Debugger::wait_for_signal() {
        auto stop = m_tracee.wait();
        m_process_state = stop.reason;

        switch (stop.reason) {
            case StopReason::exited: {
                std::println("Process exited with status {}", stop.status);
                return stop;
            }
            case StopReason::signaled: {
                std::println("Process terminated by signal {}", signal_name(stop.signal_number));
                return stop;
            }
            case StopReason::stopped: {
                break;
            }
        }
        if (!stop.signal_info) {
            return stop;
        }
        switch (stop.signal_info->si_signo) {
            case SIGTRAP: {
                handle_sigtrap(*stop.signal_info);
                break;
            }
            case SIGSEGV: {
                std::println("Segfault. Reason: {}", stop.signal_info->si_code);
                break;
            }
            default: {
                std::println("Got signal {}", signal_name(stop.signal_info->si_signo));
            }
        }

        return stop;
    }

    void Debugger::initialise_load_address() {
        if (!m_debug_info.is_dynamic()) {
            return;
        }
        std::ifstream map("/proc/" + std::to_string(m_tracee.pid()) + "/maps");
        if (!map) {
            throw std::runtime_error("Cannot open process maps");
        }
        std::string address;
        std::getline(map, address, '-');
        m_load_address = RuntimeAddress{std::stoull(address, nullptr, 16)};
    }

    DwarfAddress Debugger::to_dwarf_address(RuntimeAddress address) const {
        return DwarfAddress{address.value - m_load_address.value};
    }

    RuntimeAddress Debugger::to_runtime_address(DwarfAddress address) const {
        return RuntimeAddress{address.value + m_load_address.value};
    }

    DwarfAddress Debugger::offset_program_counter() const {
        return to_dwarf_address(m_tracee.program_counter());
    }

    void Debugger::print_source(std::string_view file_name, unsigned line, unsigned n_lines_context) {
        std::ifstream file{std::string{file_name}};

        auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
        auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;
        char c{};
        auto current_line = 1u;

        while (current_line != start_line && file.get(c)) {
            if (c == '\n') {
                ++current_line;
            }
        }

        std::print("{}", current_line == line ? "> " : " ");

        while (current_line <= end_line && file.get(c)) {
            std::print("{}", c);
            if (c == '\n') {
                ++current_line;
                std::print("{}", current_line == line ? "> " : " ");
            }
        }

        std::println("");
    }

    void Debugger::handle_sigtrap(siginfo_t info) {
        switch (info.si_code) {
            case 0: {
                return;
            }
            case SI_KERNEL:
            case TRAP_BRKPT: {
                auto breakpoint_address = RuntimeAddress{m_tracee.program_counter().value - 1};
                if (!m_breakpoints.contains(breakpoint_address)) {
                    return;
                }

                m_tracee.set_program_counter(breakpoint_address);
                std::println("Hit breakpoint at address 0x{:x}", m_tracee.program_counter().value);
                print_source_from_program_counter(m_tracee.program_counter());
                return;
            }
            case TRAP_TRACE: {
                return;
            }
            default: {
                std::println("Unknown SIGTRAP code {}", info.si_code);
                return;
            }
        }
    }

    void Debugger::print_source_from_program_counter(RuntimeAddress program_counter) {
        auto location = m_debug_info.source_location(to_dwarf_address(program_counter));
        if (!location) {
            std::println("No source line entry for address 0x{:x}", program_counter.value);
            return;
        }

        print_source(location->file, location->line);
    }

    void Debugger::single_step_instruction() {
        m_tracee.single_step();
        wait_for_signal();
    }

    void Debugger::single_step_instruction_with_breakpoint_check() {
        if (m_breakpoints.contains(m_tracee.program_counter())) {
            step_over_breakpoint();
        } else {
            single_step_instruction();
        }
    }

    void Debugger::step_over_breakpoint() {
        auto it = m_breakpoints.find(m_tracee.program_counter());
        if (it == m_breakpoints.end() || !it->second.is_enabled()) {
            return;
        }

        it->second.disable();
        m_tracee.single_step();
        wait_for_signal();
        it->second.enable();
    }

    void Debugger::step_out() {
        auto frame_pointer = m_tracee.read_register(Register::rbp);
        auto return_address = RuntimeAddress{m_tracee.read_word(RuntimeAddress{frame_pointer + 8})};
        bool should_remove_breakpoint = false;

        if (!m_breakpoints.contains(return_address)) {
            set_breakpoint_at_address(return_address);
            should_remove_breakpoint = true;
        }

        continue_execution();

        if (should_remove_breakpoint) {
            remove_breakpoint(return_address);
        }
    }

    void Debugger::remove_breakpoint(RuntimeAddress address) {
        auto it = m_breakpoints.find(address);
        if (it == m_breakpoints.end()) {
            return;
        }

        if (it->second.is_enabled()) {
            it->second.disable();
        }

        m_breakpoints.erase(it);
    }

    void Debugger::step_in() {
        auto line = m_debug_info.line_entry_from_pc(offset_program_counter())->line;

        while (m_debug_info.line_entry_from_pc(offset_program_counter())->line == line) {
            single_step_instruction_with_breakpoint_check();
        }

        print_source_from_program_counter(m_tracee.program_counter());
    }

    void Debugger::step_over() {
        auto func = m_debug_info.function_from_pc(offset_program_counter());
        auto func_entry = DwarfAddress{at_low_pc(func)};
        auto func_end = DwarfAddress{at_high_pc(func)};
        auto line = m_debug_info.line_entry_from_pc(func_entry);
        auto start_line = m_debug_info.line_entry_from_pc(offset_program_counter());
        std::vector<RuntimeAddress> to_delete;

        while (line->address < func_end.value) {
            auto load_address = to_runtime_address(DwarfAddress{line->address});
            if (line->address != start_line->address && !m_breakpoints.contains(load_address)) {
                set_breakpoint_at_address(load_address);
                to_delete.push_back(load_address);
            }
            ++line;
        }

        auto frame_pointer = m_tracee.read_register(Register::rbp);
        auto return_address = RuntimeAddress{m_tracee.read_word(RuntimeAddress{frame_pointer + 8})};
        if (!m_breakpoints.contains(return_address)) {
            set_breakpoint_at_address(return_address);
            to_delete.push_back(return_address);
        }

        continue_execution();

        for (auto address : to_delete) {
            remove_breakpoint(address);
        }
    }

    void Debugger::set_breakpoint_at_function(std::string_view name) {
        for (auto address : m_debug_info.function_breakpoints(name)) {
            set_breakpoint_at_address(to_runtime_address(address));
        }
    }

    void Debugger::set_breakpoint_at_source_line(std::string_view file, unsigned line) {
        auto address = m_debug_info.source_line_breakpoint(file, line);
        if (!address) {
            std::println("No source line entry for {}:{}", file, line);
            return;
        }

        set_breakpoint_at_address(to_runtime_address(*address));
    }

    void Debugger::print_backtrace() {
        auto output_frame = [frame_number = 0] (auto&& func) mutable {
            std::println(
                    "frame #{}: 0x{:x} {}",
                    frame_number++,
                    dwarf::at_low_pc(func),
                    dwarf::at_name(func)
            );
        };

        auto current_func = m_debug_info.function_from_pc(offset_program_counter());
        output_frame(current_func);

        auto frame_pointer = m_tracee.read_register(Register::rbp);
        auto return_address = RuntimeAddress{m_tracee.read_word(RuntimeAddress{frame_pointer + 8})};
        while (dwarf::at_name(current_func) != "main") {
            current_func = m_debug_info.function_from_pc(to_dwarf_address(return_address));
            output_frame(current_func);
            frame_pointer = m_tracee.read_word(RuntimeAddress{frame_pointer});
            return_address = RuntimeAddress{m_tracee.read_word(RuntimeAddress{frame_pointer + 8})};
        }
    }

    class ptrace_expr_context : public dwarf::expr_context {
        public:
            explicit ptrace_expr_context(const Tracee& tracee) : m_tracee{tracee} {}

            dwarf::taddr reg(unsigned reg_num) override {
                return m_tracee.read_dwarf_register(reg_num);
            }

            dwarf::taddr deref_size(dwarf::taddr address, unsigned size) override {
                auto data = m_tracee.read_word(RuntimeAddress{address});
                if (size >= sizeof(data)) {
                    return data;
                }
                return data & ((1ULL << (size * 8)) - 1);
            }

        private:
            const Tracee& m_tracee;
    };

    void Debugger::read_variables() {
        using namespace dwarf;

        auto func = m_debug_info.function_from_pc(offset_program_counter());
        for (const auto& die : func) {
            if (die.tag != DW_TAG::variable) {
                continue;
            }

            auto loc_val = die[DW_AT::location];
            if (loc_val.get_type() != value::type::exprloc) {
                continue;
            }

            ptrace_expr_context context{m_tracee};
            auto result = loc_val.as_exprloc().evaluate(&context);
            switch (result.location_type) {
                case expr_result::type::address: {
                    auto value = m_tracee.read_word(RuntimeAddress{result.value});
                    std::println("{}(0x{:x}) ={}", at_name(die), result.value, value);
                    break;
                }
                case expr_result::type::reg: {
                    auto value = m_tracee.read_dwarf_register(result.value);
                    std::println("{} (reg {}) = {}", at_name(die), result.value, value);
                    break;
                }
                default: {
                    throw std::runtime_error("Unhandled variable location");
                }
            }
        }
    }
}
