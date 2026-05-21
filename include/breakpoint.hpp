#pragma once

#include <cstdint>

#include "address.hpp"
#include "tracee.hpp"

namespace dbg {
    class Breakpoint {
        public:
            Breakpoint(Tracee& tracee, RuntimeAddress address);

            void enable();
            void disable();

            [[nodiscard]]
            bool is_enabled() const noexcept { return m_enabled; }

            [[nodiscard]]
            RuntimeAddress address() const noexcept { return m_address; }

        private:
            Tracee* m_tracee;
            RuntimeAddress m_address;
            std::uint8_t m_saved_data = 0;
            bool m_enabled = false;
    };
}
