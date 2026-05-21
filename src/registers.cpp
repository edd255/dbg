#include "../include/registers.hpp"

#include <ranges>
#include <stdexcept>

namespace dbg {
    std::uint64_t read_register_value(const user_regs_struct& regs, Register reg) {
        switch (reg) {
            case Register::rax: return regs.rax;
            case Register::rbx: return regs.rbx;
            case Register::rcx: return regs.rcx;
            case Register::rdx: return regs.rdx;
            case Register::rdi: return regs.rdi;
            case Register::rsi: return regs.rsi;
            case Register::rbp: return regs.rbp;
            case Register::rsp: return regs.rsp;
            case Register::r8: return regs.r8;
            case Register::r9: return regs.r9;
            case Register::r10: return regs.r10;
            case Register::r11: return regs.r11;
            case Register::r12: return regs.r12;
            case Register::r13: return regs.r13;
            case Register::r14: return regs.r14;
            case Register::r15: return regs.r15;
            case Register::rip: return regs.rip;
            case Register::rflags: return regs.eflags;
            case Register::cs: return regs.cs;
            case Register::orig_rax: return regs.orig_rax;
            case Register::fs_base: return regs.fs_base;
            case Register::gs_base: return regs.gs_base;
            case Register::fs: return regs.fs;
            case Register::gs: return regs.gs;
            case Register::ss: return regs.ss;
            case Register::ds: return regs.ds;
            case Register::es: return regs.es;
        }
        throw std::out_of_range("Unknown register");
    }

    void write_register_value(user_regs_struct& regs, Register reg, std::uint64_t value) {
        switch (reg) {
            case Register::rax: regs.rax = value; return;
            case Register::rbx: regs.rbx = value; return;
            case Register::rcx: regs.rcx = value; return;
            case Register::rdx: regs.rdx = value; return;
            case Register::rdi: regs.rdi = value; return;
            case Register::rsi: regs.rsi = value; return;
            case Register::rbp: regs.rbp = value; return;
            case Register::rsp: regs.rsp = value; return;
            case Register::r8: regs.r8 = value; return;
            case Register::r9: regs.r9 = value; return;
            case Register::r10: regs.r10 = value; return;
            case Register::r11: regs.r11 = value; return;
            case Register::r12: regs.r12 = value; return;
            case Register::r13: regs.r13 = value; return;
            case Register::r14: regs.r14 = value; return;
            case Register::r15: regs.r15 = value; return;
            case Register::rip: regs.rip = value; return;
            case Register::rflags: regs.eflags = value; return;
            case Register::cs: regs.cs = value; return;
            case Register::orig_rax: regs.orig_rax = value; return;
            case Register::fs_base: regs.fs_base = value; return;
            case Register::gs_base: regs.gs_base = value; return;
            case Register::fs: regs.fs = value; return;
            case Register::gs: regs.gs = value; return;
            case Register::ss: regs.ss = value; return;
            case Register::ds: regs.ds = value; return;
            case Register::es: regs.es = value; return;
        }
        throw std::out_of_range("Unknown register");
    }

    std::uint64_t get_register_value_from_dwarf_register(const user_regs_struct& regs, unsigned reg_num) {
        auto it = std::ranges::find(descriptors, static_cast<int>(reg_num), &Descriptor::dwarf);
        if (it == descriptors.end()) {
            throw std::out_of_range("Unknown dwarf register");
        }
        return read_register_value(regs, it->reg);
    }

    std::string_view get_register_name(Register reg) {
        auto it = std::ranges::find(descriptors, reg, &Descriptor::reg);
        if (it == descriptors.end()) {
            throw std::out_of_range("Unknown register");
        }
        return it->name;
    }

    std::optional<Register> find_register_from_name(std::string_view name) {
        auto it = std::ranges::find(descriptors, name, &Descriptor::name);
        if (it == descriptors.end()) {
            return std::nullopt;
        }
        return it->reg;
    }

    Register get_register_from_name(std::string_view name) {
        auto reg = find_register_from_name(name);
        if (!reg) {
            throw std::out_of_range("Unknown register name");
        }
        return *reg;
    }
}
