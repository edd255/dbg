#include <algorithm>
#include <fstream>
#include <iomanip>
#include <ios>
#include <iostream>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "../include/registers.hpp"
#include "../include/debugger.hpp"

using namespace dbg;

void execute_debugee(const std::string& program)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(program.c_str(), program.c_str(), nullptr);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }
    const std::string usage =
        "Debugger -- Version 0.0.1\n"
        "Commands:\n"
        "\t continue:\t             Step over breakpoint\n"
        "\t break <addr>:\t\t     Set breakpoint at <addr>\n"
        "\t register\n"
        "\t\t dump:               Print register values\n"
        "\t\t read <reg:          Print value at register <reg>\n"
        "\t\t write <reg> <val:   Write <val> to register <reg>\n"
        "\t memory\n"
        "\t\t read <addr>:        Read value at address <addr>\n"
        "\t\t write <addr> <val>: Write <val> at address <addr>\n"
    ;
    std::cout << usage;
    auto program = argv[1];
    auto pid = fork();
    if (pid == 0) {
        // we're in the child process
        // execute debugee
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(program);
    } else if (pid >= 1) {
        // we're in the parent process
        // execute debugger
        std::cout << "Starting debugging process " << pid << '\n';
        Debugger dbg(program, pid);
        dbg.run();
    }
}

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
    } else if (is_prefix(command, "stepi")) {
        single_step_instruction_with_breakpoint_check();
        auto line_entry = get_line_entry_from_program_counter(get_program_counter());
        print_source(line_entry -> file -> path, line_entry -> line);
    } else if (is_prefix(command, "step")) {
        step_in();
    } else if (is_prefix(command, "next")) {
        step_over();
    } else if (is_prefix(command, "finish")) {
        step_out();
    } else if (is_prefix(command, "break")) {
        if (args[1][0] == '0' && args[1][1] == 'x') {
            std::string address{args[1], 2};
            set_breakpoint_at_address(std::stol(address, nullptr, 16));
        } else if (args[1].find(':') != std::string::npos) {
            auto file_and_line = split(args[1], ':');
            set_breakpoint_at_source_line(file_and_line[0], std::stoi(file_and_line[1]));
        } else {
            set_breakpoint_at_function(args[1]);
        }
    } else if (is_prefix(command, "symbol")) {
        auto symbols = lookup_symbol(args[1]);
        for (auto&& _symbol : symbols) {
            std::cout
                << _symbol.name
                << ' '
                << symbol_to_string(_symbol.type)
                << " 0x"
                << std::hex
                << _symbol.address
                << std::endl;
        }
    } else if (is_prefix(command, "backtrace")) {
        print_backtrace();
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

dwarf::die Debugger::get_function_from_program_counter(uint64_t program_counter)
{
    for (auto &cu : m_debug_info.compilation_units()) {
        if (die_pc_range(cu.root()).contains(program_counter)) {
            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram) {
                    if (die_pc_range(die).contains(program_counter)) {
                        return die;
                    }
                }
            }
        }
    }
    throw std::out_of_range("Cannot find function");
}

dwarf::line_table::iterator Debugger::get_line_entry_from_program_counter(uint64_t program_counter) {
    for (auto &cu : m_debug_info.compilation_units()) {
        if (die_pc_range(cu.root()).contains(program_counter)) {
            auto &lt = cu.get_line_table();
            auto it = lt.find_address(program_counter);
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
            // put the program_counter back where it should be
            set_program_counter(get_program_counter() - 1);
            std::cout 
                << "Hit breakpoint at address 0x" 
                << std::hex 
                << get_program_counter()
                << std::endl;
            uint64_t offset_pc = offset_load_address(get_program_counter());
            dwarf::line_table::iterator line_entry = get_line_entry_from_program_counter(offset_pc);
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

void Debugger::single_step_instruction()
{
    ptrace(PTRACE_SINGLESTEP, m_process_id, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::single_step_instruction_with_breakpoint_check()
{
    if (m_breakpoints.count(get_program_counter())) {
        step_over_breakpoint();
    } else {
        single_step_instruction();
    }
}

void Debugger::step_out()
{
    auto frame_pointer = get_register_value(m_process_id, Register::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    bool should_remove_breakpoint = false;
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        should_remove_breakpoint = true;
    }
    continue_execution();
    if (should_remove_breakpoint) {
        remove_breakpoint(return_address);
    }
}

void Debugger::remove_breakpoint(std::intptr_t address)
{
    if (m_breakpoints.at(address).is_enabled()) {
        m_breakpoints.at(address).disable();
    }
    m_breakpoints.erase(address);
}

void Debugger::step_in()
{
    auto line = get_line_entry_from_program_counter(get_offset_program_counter()) -> line;
    while (get_line_entry_from_program_counter(get_offset_program_counter()) -> line == line) {
        single_step_instruction_with_breakpoint_check();
    }
    auto line_entry = get_line_entry_from_program_counter(get_offset_program_counter());
    print_source(line_entry -> file -> path, line_entry -> line);
}

uint64_t Debugger::get_offset_program_counter()
{
    return offset_load_address(get_program_counter());
}

uint64_t Debugger::offset_dwarf_address(uint64_t address)
{
    return address + m_load_address;
}

void Debugger::step_over()
{
    auto func = get_function_from_program_counter(get_offset_program_counter());
    auto func_entry = at_low_pc(func);
    auto func_end = at_high_pc(func);
    auto line = get_line_entry_from_program_counter(func_entry);
    auto start_line = get_line_entry_from_program_counter(get_offset_program_counter());
    std::vector<std::intptr_t> to_delete{};
    while (line -> address < func_end) {
        auto load_address = offset_dwarf_address(line -> address);
        if (line -> address != start_line -> address && !m_breakpoints.count(load_address)) {
            set_breakpoint_at_address(load_address);
            to_delete.push_back(load_address);
        }
        ++line;
    }
    auto frame_pointer = get_register_value(m_process_id, Register::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    if (!m_breakpoints.count(return_address)) {
        set_breakpoint_at_address(return_address);
        to_delete.push_back(return_address);
    }
    continue_execution();
    for (auto address : to_delete) {
        remove_breakpoint(address);
    }
}

void Debugger::set_breakpoint_at_function(const std::string& name)
{
    for (const auto& cu : m_debug_info.compilation_units()) {
        for (const auto& die : cu.root()) {
            if (die.has(dwarf::DW_AT::name) && at_name(die) == name) {
                auto low_pc = at_low_pc(die);
                auto entry = get_line_entry_from_program_counter(low_pc);
                ++entry; // skip prologue
                set_breakpoint_at_address(offset_dwarf_address(entry -> address));
            }
        }
    }
}

bool is_suffix(const std::string& s, const std::string& of) {
    if (s.size() > of.size()) {
        return false;
    }
    auto diff = of.size() - s.size();
    return std::equal(s.begin(), s.end(), of.begin() + diff);
}

void Debugger::set_breakpoint_at_source_line(const std::string& file, unsigned line)
{
    for (const auto& compilation_unit : m_debug_info.compilation_units()) {
        if (is_suffix(file, at_name(compilation_unit.root()))) {
            const auto& lt = compilation_unit.get_line_table();
            for (const auto& entry : lt) {
                if (entry.is_stmt && entry.line == line) {
                    set_breakpoint_at_address(offset_dwarf_address(entry.address));
                    return;
                }
            }
        }
    }
}

symbol_type to_symbol_type(elf::stt _symbol)
{
    switch (_symbol) {
        case elf::stt::notype: {
            return symbol_type::notype;
        }
        case elf::stt::object: {
            return symbol_type::object;
        }
        case elf::stt::func: {
            return symbol_type::func;
        }
        case elf::stt::section: {
            return symbol_type::section;
        }
        case elf::stt::file: {
            return symbol_type::file;
        }
        default:
            return symbol_type::notype;
    }
}

std::vector<symbol> Debugger::lookup_symbol(const std::string& name)
{
    std::vector<symbol> symbols;
    for (auto& section : m_elf.sections()) {
        if (1) {
            continue;
        }
        for (auto _symbol : section.as_symtab()) {
            if (_symbol.get_name() == name) {
                auto& d = _symbol.get_data();
                symbols.push_back(symbol{to_symbol_type(d.type()), _symbol.get_name(), d.value});
            }
        }
    }

    return symbols;
}

void Debugger::print_backtrace()
{
    auto output_frame = [frame_number = 0] (auto&& func) mutable {
        std::cout
            << "frame #"
            << frame_number++
            << ": 0x"
            << dwarf::at_low_pc(func)
            << " "
            << dwarf::at_name(func)
            << std::endl;
    };
    auto current_func = get_function_from_program_counter(get_program_counter());
    output_frame(current_func);
    auto frame_pointer = get_register_value(m_process_id, Register::rbp);
    auto return_address = read_memory(frame_pointer + 8);
    while (dwarf::at_name(current_func) != "main") {
        current_func = get_function_from_program_counter(return_address);
        output_frame(current_func);
        frame_pointer = read_memory(frame_pointer);
        return_address = read_memory(frame_pointer + 8);
    }
}
