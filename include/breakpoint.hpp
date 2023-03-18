#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <iostream>
#include <sys/ptrace.h>

namespace dbg {
    class Breakpoint {
        private:
            pid_t m_process_id;
            std::intptr_t m_address;
            bool m_enabled;
            uint8_t m_saved_data;

        public:
            Breakpoint() = default;
            Breakpoint(pid_t process_id, std::intptr_t address) : 
                m_process_id{process_id}, m_address{address}, m_enabled{false}, m_saved_data{} 
            {}

            void enable()
            {
                auto data = ptrace(PTRACE_PEEKDATA, m_process_id, m_address, nullptr);
                m_saved_data = static_cast<uint8_t>(data & 0xff);
                uint64_t int3 = 0xcc;
                uint64_t data_with_int3 = ((data & ~0xff) | int3);
                ptrace(PTRACE_POKEDATA, m_process_id, m_address, data_with_int3);
                m_enabled = true;
            }

            void disable()
            {
                auto data = ptrace(PTRACE_PEEKDATA, m_process_id, m_address, nullptr);
                auto restored_data = ((data & ~0xff) | m_saved_data);
                ptrace(PTRACE_POKEDATA, m_process_id, m_address, restored_data);
                m_enabled = false;
            }

            bool is_enabled()
            {
                return m_enabled;
            }

            std::intptr_t get_address()
            {
                return m_address;
            }
    };
}

#endif
