#include "../include/tracee.hpp"

#include <cerrno>
#include <cstdint>
#include <system_error>
#include <sys/ptrace.h>
#include <sys/wait.h>

namespace dbg {
    std::uint64_t Tracee::read_word(RuntimeAddress address) const {
        errno = 0;
        auto data = ptrace(PTRACE_PEEKDATA, m_pid, address.value, nullptr);
        if (data == -1 && errno != 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace PEEKDATA");
        }
        return static_cast<std::uint64_t>(data);
    }

    void Tracee::write_word(RuntimeAddress address, std::uint64_t value) const {
        if (ptrace(PTRACE_POKEDATA, m_pid, address.value, value) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace POKEDATA");
        }
    }

    user_regs_struct Tracee::registers() const {
        user_regs_struct regs{};
        if (ptrace(PTRACE_GETREGS, m_pid, nullptr, &regs) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace GETREGS");
        }
        return regs;
    }

    void Tracee::set_registers(const user_regs_struct& regs) const {
        if (ptrace(PTRACE_SETREGS, m_pid, nullptr, &regs) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace SETREGS");
        }
    }

    std::uint64_t Tracee::read_register(Register reg) const {
        return read_register_value(registers(), reg);
    }

    void Tracee::write_register(Register reg, std::uint64_t value) const {
        auto regs = registers();
        write_register_value(regs, reg, value);
        set_registers(regs);
    }

    std::uint64_t Tracee::read_dwarf_register(unsigned reg_num) const {
        return get_register_value_from_dwarf_register(registers(), reg_num);
    }

    RuntimeAddress Tracee::program_counter() const {
        return RuntimeAddress{read_register(Register::rip)};
    }

    void Tracee::set_program_counter(RuntimeAddress program_counter) const {
        write_register(Register::rip, program_counter.value);
    }

    void Tracee::resume() const {
        if (ptrace(PTRACE_CONT, m_pid, nullptr, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace CONT");
        }
    }

    void Tracee::single_step() const {
        if (ptrace(PTRACE_SINGLESTEP, m_pid, nullptr, nullptr) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace SINGLESTEP");
        }
    }

    StopInfo Tracee::wait() const {
        int wait_status = 0;
        if (waitpid(m_pid, &wait_status, 0) < 0) {
            throw std::system_error(errno, std::generic_category(), "waitpid");
        }

        if (WIFEXITED(wait_status)) {
            return StopInfo{StopReason::exited, WEXITSTATUS(wait_status)};
        }

        if (WIFSIGNALED(wait_status)) {
            return StopInfo{StopReason::signaled, 0, WTERMSIG(wait_status)};
        }

        return StopInfo{StopReason::stopped, 0, WSTOPSIG(wait_status), signal_info()};
    }

    siginfo_t Tracee::signal_info() const {
        siginfo_t info{};
        if (ptrace(PTRACE_GETSIGINFO, m_pid, nullptr, &info) < 0) {
            throw std::system_error(errno, std::generic_category(), "ptrace GETSIGINFO");
        }
        return info;
    }
}
