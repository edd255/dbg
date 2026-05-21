#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "address.hpp"
#include "../libs/libelfin/elf/elf++.hh"
#include "../libs/libelfin/dwarf/dwarf++.hh"

namespace dbg {
    enum class symbol_type {
        notype,
        object,
        func,
        section,
        file,
    };

    [[nodiscard]] std::string symbol_to_string(symbol_type type);

    struct Symbol {
        symbol_type type;
        std::string name;
        std::uintptr_t address;
    };

    struct SourceLocation {
        std::string file;
        unsigned line = 0;
    };

    class DebugInfo {
        public:
            explicit DebugInfo(std::string program_name);

            [[nodiscard]]
            bool is_dynamic() const;

            [[nodiscard]]
            dwarf::die function_from_pc(DwarfAddress program_counter) const;

            [[nodiscard]]
            dwarf::line_table::iterator line_entry_from_pc(DwarfAddress program_counter) const;

            [[nodiscard]]
            std::optional<SourceLocation> source_location(DwarfAddress program_counter) const;

            [[nodiscard]]
            std::vector<DwarfAddress> function_breakpoints(std::string_view name) const;

            [[nodiscard]]
            std::optional<DwarfAddress> source_line_breakpoint(std::string_view file, unsigned line) const;

            [[nodiscard]]
            std::vector<Symbol> lookup_symbol(std::string_view name) const;

        private:
            std::string m_program_name;
            dwarf::dwarf m_dwarf;
            elf::elf m_elf;
    };
}
