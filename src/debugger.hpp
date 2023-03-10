#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <fcntl.h>
#include <utility>
#include <string>
#include <signal.h>
#include <unordered_map>

#include "breakpoint.hpp"
#include "registers.hpp"
#include "../libs/linenoise/linenoise.h"
#include "../libs/libelfin/elf/elf++.hh"
#include "../libs/libelfin/dwarf/dwarf++.hh"

class Debugger
{
    private:
        std::string m_program_name;
        pid_t m_process_id;
        std::unordered_map<std::intptr_t, Breakpoint> m_breakpoints;
        dwarf::dwarf m_debug_info;
        elf::elf m_elf;
        uint64_t m_load_address = 0;

        void handle_command(const std::string& line);
        static std::vector<std::string> split(const std::string& s, char delimiter);
        static bool is_prefix(const std::string& s, const std::string& of);
        void continue_execution();
        uint64_t read_memory(uint64_t address) const;
        void write_memory(uint64_t address, uint64_t value) const;
        uint64_t get_program_counter() const;
        void set_program_counter(uint64_t program_counter) const;
        void step_over_breakpoint();
        void wait_for_signal();
        dwarf::die get_function_from_program_counter(uint64_t program_counter);
        dwarf::line_table::iterator get_line_entry_from_program_counter(uint64_t program_counter);
        void initialise_load_address();
        uint64_t offset_load_address(uint64_t addr) const;
        siginfo_t get_signal_info() const;
        void handle_sigtrap(siginfo_t info);
        void single_step_instruction();
        void single_step_instruction_with_breakpoint_check();
        void step_out();
        void remove_breakpoint(std::intptr_t address);
        void step_in();
        uint64_t get_offset_program_counter();
        uint64_t offset_dwarf_address(uint64_t address);
        void step_over();

    public:
        Debugger(std::string program_name, pid_t process_id)
        {
            m_program_name = std::move(program_name);
            m_process_id = process_id;
            auto fd = open(m_program_name.c_str(), O_RDONLY);
            m_elf = elf::elf{elf::create_mmap_loader(fd)};
            m_debug_info = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
        }
        void run();
        void set_breakpoint_at_address(std::intptr_t address);
        void dump_registers() const;
        static void print_source(const std::string& file_name, unsigned line, unsigned n_lines_context = 2);
};

#endif
