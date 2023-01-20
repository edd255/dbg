#include <iostream>
#include <algorithm>
#include <sys/user.h>
#include <sys/ptrace.h>
#include "registers.hpp"

uint64_t get_register_value(pid_t pid, Register reg)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto it = std::find_if(
        begin(descriptors), end(descriptors),
        [reg](auto&&rd) { return rd.r == reg; }
    );
    return *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(descriptors)));
}


void set_register_value(pid_t pid, Register reg, uint64_t value)
{
    user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, nullptr, &regs);
    auto it = std::find_if(
        begin(descriptors), end(descriptors),
        [reg](auto&& rd) { return rd.reg == reg; }
    );
    *(reinterpret_cast<uint64_t*>(&regs) + (it - begin(descriptors))) = value;
    ptrace(PTRACE_SETREGS, pid, nullptr, &regs);
}

uint64_t get_register_value_from_dwarf_register(pid_t pid, unsigned reg_num)
{
    auto it = std::find_if(
        begin(descriptors), end(descriptors),
        [reg_num](auto&& rd) { return rd.dwarf == reg_num; }
    );
    if (it == end(descriptors)) {
        throw std::out_of_range("Unknown dwarf rgister");
    }
    return get_register_value(pid, it -> reg);
}

std::string get_register_name(Register reg)
{
    auto it = std::find_if(
        begin(descriptors), end(descriptors),
        [reg](auto&& rd) { return rd.reg == reg; }
    );
    return it -> name;
}

Register get_register_from_name(const std::string& name)
{
    auto it = std::find_if(
        begin(descriptors), end(descriptors),
        [name](auto&& rd) { return rd.name == name; }
    );
    return it -> reg;
}
