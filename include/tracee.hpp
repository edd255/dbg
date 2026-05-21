#pragma once

#include <cstdint>
#include <optional>
#include <signal.h>
#include <sys/types.h>
#include <sys/user.h>

#include "address.hpp"
#include "registers.hpp"

namespace dbg {
    enum class StopReason {
        stopped,
        exited,
        signaled,
    };

    struct StopInfo {
        StopReason reason;
        int status = 0;
        int signal_number = 0;
        std::optional<siginfo_t> signal_info;
    };

    class Tracee {
        public:
            explicit Tracee(pid_t pid) : m_pid{pid} {}

            [[nodiscard]]
            pid_t pid() const noexcept {
                return m_pid;
            }

            [[nodiscard]]
            std::uint64_t read_word(RuntimeAddress address) const;
            void write_word(RuntimeAddress address, std::uint64_t value) const;

            [[nodiscard]]
            user_regs_struct registers() const;
            void set_registers(const user_regs_struct& registers) const;

            [[nodiscard]]
            std::uint64_t read_register(Register reg) const;
            void write_register(Register reg, std::uint64_t value) const;
            [[nodiscard]]
            std::uint64_t read_dwarf_register(unsigned reg_num) const;

            [[nodiscard]]
            RuntimeAddress program_counter() const;
            void set_program_counter(RuntimeAddress program_counter) const;

            void resume() const;
            void single_step() const;

            [[nodiscard]]
            StopInfo wait() const;

            [[nodiscard]]
            siginfo_t signal_info() const;

        private:
            pid_t m_pid;
    };
}
