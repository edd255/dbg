#include "../include/breakpoint.hpp"

#include <cstdint>

namespace dbg {
    Breakpoint::Breakpoint(
        Tracee& tracee,
        RuntimeAddress address
    ) : m_tracee{&tracee}, m_address{address} {}

    void Breakpoint::enable() {
        auto data = m_tracee->read_word(m_address);
        m_saved_data = static_cast<std::uint8_t>(data & 0xff);
        auto data_with_int3 = (data & ~0xffULL) | 0xcc;
        m_tracee->write_word(m_address, data_with_int3);
        m_enabled = true;
    }

    void Breakpoint::disable() {
        auto data = m_tracee->read_word(m_address);
        auto restored_data = (data & ~0xffULL) | m_saved_data;
        m_tracee->write_word(m_address, restored_data);
        m_enabled = false;
    }
}
