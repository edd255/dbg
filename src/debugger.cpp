#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include "debugger.hpp"
#include "../libs/linenoise/linenoise.h"

void Debugger::run()
{
    int wait_status;
    auto options = 0;
    waitpid(process_id, &wait_status, options);
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
        set_breakpoint_at_address(std::stol(address, 0, 16));
    } else if (is_prefix(command, "register")) {
        if (is_prefix(args[1], "dump")) {
            dump_registers();
        } else if (is_prefix(args[1], "read")) {
            std::cout
                << "0x"
                << get_register_value(
                    process_id,
                    get_register_from_name(args[2])
                )
                << std::endl;
        } else if (is_prefix(args[1], "write")) {
            std::string val(args[3], 2);
            set_register_value(
                    process_id,
                    get_register_from_name(args[2]),
                    std::stol(val, 0, 16)
                );
        }
    } else if (is_prefix(command, "memory")) {
        std::string address(args[2], 2);
        if (is_prefix(args[1], "read")) {
            std::cout
                << std::hex
                << read_memory(std::stol(address, 0, 16))
                << std::endl;
        }
        if (is_prefix(args[1], "write")) {
            std::string value(args[3], 2);
            write_memory(
                    std::stol(address, 0, 16),
                    std::stol(value, 0, 16)
                );
        }
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
    ptrace(PTRACE_CONT, process_id, nullptr, nullptr);
    wait_for_signal();
}

void Debugger::set_breakpoint_at_address(std::intptr_t address)
{
    std::cout
        << "Set breakpoint at address 0x"
        << std::hex
        << address
        << std::endl;
    Breakpoint breakpoint {process_id, address};
    breakpoint.enable();
    breakpoints[address] = breakpoint;
}

void Debugger::dump_registers()
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
            << get_register_value(process_id, descriptor.reg)
            << std::endl;
    }
}

uint64_t Debugger::read_memory(uint64_t address)
{
    return ptrace(PTRACE_PEEKDATA, process_id, address, nullptr);
}

void Debugger::write_memory(uint64_t address, uint64_t value)
{
    ptrace(PTRACE_POKEDATA, process_id, address, value);
}

uint64_t Debugger::get_program_counter()
{
    return get_register_value(process_id, Register::rip);
}

void Debugger::set_program_conter(uint64_t program_counter)
{
    set_register_value(process_id, Register::rip, program_counter);
}

void Debugger::step_over_breakpoint()
{
    auto possible_breakpoint_location = get_program_counter() - 1;
    if (breakpoints.count(possible_breakpoint_location)) {
        auto& breakpoint = breakpoints[possible_breakpoint_location];
        if (breakpoint.is_enabled()) {
            auto previous_instruction_address = possible_breakpoint_location;
            set_program_conter(previous_instruction_address);
            breakpoint.disable();
            ptrace(PTRACE_SINGLESTEP, process_id, nullptr, nullptr);
            wait_for_signal();
            breakpoint.enable();
        }
    }
}

void Debugger::wait_for_signal()
{
    int wait_status;
    auto options = 0;
    waitpid(process_id, &wait_status, options);
}
