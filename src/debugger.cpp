#include <vector>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <fstream>
#include <iostream>
#include <iomanip>

#include "debugger.hpp"

void Debugger::run()
{
    wait_for_signal();
    initialise_load_address();
    char* line = nullptr;
    while ((line = linenoise("> ")) != nullptr) {
        handle_command(line);
        linenoiseHistoryAdd(line);
        linenoiseFree(line);
    }
}

void Debugger::handle_command(const std::string& line)
{
    auto args = split(line, ' ');
    auto command = args[0];

    if (is_prefix(command, "continue")) {
        continue_execution();
    } else if (is_prefix(command, "break")) {
        std::string address {args[1], 2};
        set_breakpoint_at_address(std::stol(address, nullptr, 16));
    } else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        } else if (is_prefix(args[1], "read")) {
            std::cout
                << "0x"
                << get_register_value(
                        m_process_id,
                        get_register_from_name(args[2])
                )
                << std::endl;
        } else if (is_prefix(args[1], "write")) {
            std::string val(args[3], 2);
            set_register_value(
                    m_process_id,
                    get_register_from_name(args[2]),
                    std::stol(val, nullptr, 16)
                );
        }
    } else if (is_prefix(command, "memory")) {
        std::string address(args[2], 2);
        if (is_prefix(args[1], "read")) {
            std::cout
                << std::hex
                << read_memory(std::stol(address, nullptr, 16))
                << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string value(args[3], 2);
            write_memory(
                    std::stol(address, nullptr, 16),
                    std::stol(value, nullptr, 16)
            );
        }
    } else if (is_prefix(command, "exit")) {
        exit(0);
    } else {
        std::cerr << "Unknown command\n";
    }
}

std::vector<std::string> Debugger::split(const std::string& s, char delimiter)
{
    std::vector<std::string> out{};
    std::stringstream ss {s};
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        out.push_back(item);
    }
    return out;
}

bool Debugger::is_prefix(const std::string& s, const std::string& of)
{
    if (s.size() > of.size()) {
        return false;
    }

    return std::equal(s.begin(), s.end(), of.begin());
}

void Debugger::continue_execution()
{
    step_over_breakpoint();
    ptrace(PTRACE_CONT, m_process_id, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::set_breakpoint_at_address(std::intptr_t address)
{
    std::cout
        << "Set breakpoint at address 0x"
        << std::hex
        << address
        << std::endl;
    Breakpoint breakpoint {m_process_id, address};
    breakpoint.enable();
    m_breakpoints[address] = breakpoint;
}

void Debugger::dump_registers() const
{
    for (const auto& descriptor : descriptors) {
        std::string tab = "\t";
        descriptor.name == "orig_rax" ? tab = " " : tab = "\t ";
        std::cout
            << descriptor.name
            << tab
            << " 0x"
            << std::setfill('0')
            << std::setw(16)
            << std::hex
            << get_register_value(m_process_id, descriptor.reg)
            << std::endl;
    }
}

uint64_t Debugger::read_memory(uint64_t address) const
{
    return ptrace(PTRACE_PEEKDATA, m_process_id, address, nullptr);
}

void Debugger::write_memory(uint64_t address, uint64_t value) const
{
    ptrace(PTRACE_POKEDATA, m_process_id, address, value);
}

uint64_t Debugger::get_program_counter() const
{
    return get_register_value(m_process_id, Register::rip);
}

void Debugger::set_program_counter(uint64_t program_counter) const
{
    set_register_value(m_process_id, Register::rip, program_counter);
}

void Debugger::step_over_breakpoint()
{
    if (m_breakpoints.count(get_program_counter())) {
        auto& breakpoint = m_breakpoints[get_program_counter()];
        if (breakpoint.is_enabled()) {
            breakpoint.disable();
            ptrace(PTRACE_SINGLESTEP, m_process_id, nullptr, nullptr);
            wait_for_signal();
            breakpoint.enable();
        }
    }
}

void Debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(m_process_id, &wait_status, options);
    auto siginfo = get_signal_info();
    switch (siginfo.si_signo) {
        case SIGTRAP: {
            handle_sigtrap(siginfo);
            break;
        }
        case SIGSEGV: {
            std::cout
                << "Segfault. Reason: "
                << siginfo.si_code
                << std::endl;
            break;
        }
        default: {
            std::cout
                << "Got signal "
                << strsignal(siginfo.si_signo)
                << std::endl;
        }
    }
}

dwarf::die Debugger::get_function_from_pc(uint64_t pc)
{
    for (auto &cu : m_debug_info.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(pc)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range("Cannot find function");
}

dwarf::line_table::iterator Debugger::get_line_entry_from_pc(uint64_t pc) {
    for (auto &cu : m_debug_info.compilation_units()) {
        if (die_pc_range(cu.root()).contains(pc)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(pc);
            if (it == lt.end()) {
                throw std::out_of_range{"Cannot find line entry"};
            } else {
                return it;
            }
        }
    }

    throw std::out_of_range{"Cannot find line entry"};
}

void Debugger::initialise_load_address()
{
    // If this is a dynamic library, e.g. a PIE
    if (m_elf.get_hdr().type == elf::et::dyn) {
        // The load address if found in /proc/<pid>/maps
        std::ifstream map("/proc/" + std::to_string(m_process_id) + "/maps");

        // Read the first address from the file
        std::string addr;
        std::getline(map, addr, '-');

        // TODO: This line causes a crash
        m_load_address = std::stol(addr, nullptr, 16);
    }
}

uint64_t Debugger::offset_load_address(uint64_t addr) const
{
    return addr - m_load_address;
}

void Debugger::print_source(const std::string& file_name, unsigned line, unsigned n_lines_context)
{
    std::ifstream file{file_name};

    // Work out a window around the desired line
    auto start_line = line <= n_lines_context ? 1 : line - n_lines_context;
    auto end_line = line + n_lines_context + (line < n_lines_context ? n_lines_context - line : 0) + 1;
    char c{};
    auto current_line = 1u;

    // Skip lines up until start_line
    while (current_line != start_line && file.get(c)) {
        if (c == '\n') {
            ++current_line;
        }
    }

    // Output cursor if we're at the current line
    std::cout << (current_line == line ? "> " : " ");

    // Write lines up until end_line
    while (current_line <= end_line && file.get(c)) {
        std::cout << c;
        if (c == '\n') {
            ++current_line;
            // Output cursor if we're at the current line
            std::cout << (current_line == line ? "> " : " ");
        }
    }
    std::cout << std::endl;
}

siginfo_t Debugger::get_signal_info() const
{
    siginfo_t info;
    ptrace(PTRACE_GETSIGINFO, m_process_id, nullptr, &info);
    return info;
}

// TODO: There are a bunch of different signals and flavours of signals which
// you could handle, see man sigaction
void Debugger::handle_sigtrap(siginfo_t info)
{
    switch (info.si_code) {
        case SI_KERNEL:
        case TRAP_BRKPT: {
            // put the pc back where it should be
            set_program_counter(get_program_counter() - 1);
            std::cout 
                << "Hit breakpoint at address 0x" 
                << std::hex 
                << get_program_counter()
                << std::endl;
            uint64_t offset_pc = offset_load_address(get_program_counter());
            dwarf::line_table::iterator line_entry = get_line_entry_from_pc(offset_pc);
            print_source(line_entry->file->path, line_entry->line);
            return;
        }
        case TRAP_TRACE: {
            return;
        }
        default: {
            std::cout << "Unknown SIGTRAP code " << info.si_code << std::endl;
            return;
        }
    }
}
