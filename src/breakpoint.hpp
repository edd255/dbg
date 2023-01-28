#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <iostream>
#include <sys/ptrace.h>

class Breakpoint
{
    private:
        pid_t process_id;
        std::intptr_t address;
        bool enabled;
        uint8_t saved_data;

    public:
        Breakpoint() = default;
        Breakpoint(pid_t process_id, std::intptr_t address) :
            process_id{process_id}, address{address}, enabled{false}, saved_data{}
        {}

        void enable()
        {
            auto data = ptrace(PTRACE_PEEKDATA, process_id, address, nullptr);
            saved_data = static_cast<uint8_t>(data & 0xff);
            uint64_t int3 = 0xcc;
            uint64_t data_with_int3 = ((data & ~0xff) | int3);
            ptrace(PTRACE_POKEDATA, process_id, address, data_with_int3);
            enabled = true;
        }

        void disable()
        {
            auto data = ptrace(PTRACE_PEEKDATA, process_id, address, nullptr);
            auto restored_data = ((data & ~0xff) | saved_data);
            ptrace(PTRACE_POKEDATA, process_id, address, restored_data);
            enabled = false;
        }

        auto is_enabled() const -> bool { return enabled; }
        auto get_address() const -> std::intptr_t { return address; }
};

#endif
