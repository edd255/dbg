#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

#include "address.hpp"
#include "breakpoint.hpp"
#include "command.hpp"
#include "debug_info.hpp"
#include "tracee.hpp"

namespace dbg {
    class Debugger {
        public:
            Debugger(std::string program_name, pid_t process_id);
            ~Debugger() noexcept;

            void run();

            void set_breakpoint_at_address(RuntimeAddress address);
            void dump_registers() const;
            static void print_source(std::string_view file_name, unsigned line, unsigned n_lines_context = 2);
            void single_step_instruction();
            void single_step_instruction_with_breakpoint_check();
            void step_out();
            void remove_breakpoint(RuntimeAddress address);
            void step_in();
            void step_over();
            void set_breakpoint_at_function(std::string_view name);
            void set_breakpoint_at_source_line(std::string_view file, unsigned line);
            void read_variables();

        private:
            void execute(const Command& command);
            void continue_execution();
            StopInfo wait_for_signal();
            void handle_sigtrap(siginfo_t info);
            void step_over_breakpoint();
            void initialise_load_address();
            void print_source_from_program_counter(RuntimeAddress program_counter);
            void print_backtrace();

            [[nodiscard]]
            DwarfAddress to_dwarf_address(RuntimeAddress address) const;

            [[nodiscard]]
            RuntimeAddress to_runtime_address(DwarfAddress address) const;

            [[nodiscard]]
            DwarfAddress offset_program_counter() const;

            std::string m_program_name;
            Tracee m_tracee;
            DebugInfo m_debug_info;
            std::unordered_map<RuntimeAddress, Breakpoint, RuntimeAddressHash> m_breakpoints;
            RuntimeAddress m_load_address{};
            StopReason m_process_state = StopReason::stopped;
            bool m_should_exit = false;
    };
}
