#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include <unordered_map>
#include "breakpoint.hpp"
#include "registers.hpp"
#include "../libs/linenoise/linenoise.h"

class Debugger
    {
    private:
        std::string program_name;
        pid_t pid;
        std::unordered_map<std::intptr_t, Breakpoint> breakpoints;

    public:
        Debugger(std::string program_name, pid_t pid) :
            program_name(std::move(program_name)), pid(pid) {}
        void run();
        void handle_command(const std::string& line);
        std::vector<std::string> split(const std::string& s, char delimiter);
        bool is_prefix(const std::string& s, const std::string& of);
        void continue_execution();
        void set_breakpoint_at_address(std::intptr_t address);
        void dump_registers();
        uint64_t read_memory(uint64_t address);
        void write_memory(uint64_t address, uint64_t value);
        uint64_t get_program_counter();
        void set_program_conter(uint64_t program_counter);
        void step_over_breakpoint();
        void wait_for_signal();
    };

#endif
