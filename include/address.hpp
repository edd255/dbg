#pragma once

#include <cstdint>
#include <functional>

namespace dbg {
    struct RuntimeAddress {
        std::uintptr_t value = 0;

        friend constexpr bool operator==(RuntimeAddress, RuntimeAddress) = default;
    };

    struct DwarfAddress {
        std::uintptr_t value = 0;

        friend constexpr bool operator==(DwarfAddress, DwarfAddress) = default;
    };

    struct RuntimeAddressHash {
        std::size_t operator()(RuntimeAddress address) const noexcept {
            return std::hash<std::uintptr_t>{}(address.value);
        }
    };
}
