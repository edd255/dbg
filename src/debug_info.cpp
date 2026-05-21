#include "../include/debug_info.hpp"

#include <cerrno>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <system_error>
#include <unistd.h>

namespace dbg {
    namespace {
        class unique_fd {
            public:
                explicit unique_fd(int fd) noexcept : m_fd{fd} {}

                unique_fd(const unique_fd&) = delete;
                unique_fd& operator=(const unique_fd&) = delete;

                unique_fd(unique_fd&& other) noexcept : m_fd{other.release()} {}

                unique_fd& operator=(unique_fd&& other) noexcept {
                    if (this != &other) {
                        reset(other.release());
                    }
                    return *this;
                }

                ~unique_fd() {
                    reset();
                }

                [[nodiscard]] int get() const noexcept {
                    return m_fd;
                }

                [[nodiscard]] int release() noexcept {
                    auto fd = m_fd;
                    m_fd = -1;
                    return fd;
                }

                void reset(int fd = -1) noexcept {
                    if (m_fd >= 0) {
                        close(m_fd);
                    }
                    m_fd = fd;
                }

            private:
                int m_fd = -1;
        };

        [[nodiscard]]
        bool is_suffix(std::string_view suffix, std::string_view text) {
            return suffix.size() <= text.size()
                && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
        }

        [[nodiscard]]
        symbol_type to_symbol_type(elf::stt symbol) {
            switch (symbol) {
                case elf::stt::notype: return symbol_type::notype;
                case elf::stt::object: return symbol_type::object;
                case elf::stt::func: return symbol_type::func;
                case elf::stt::section: return symbol_type::section;
                case elf::stt::file: return symbol_type::file;
                default: return symbol_type::notype;
            }
        }
    }

    std::string symbol_to_string(symbol_type type) {
        switch (type) {
            case symbol_type::notype: return "notype";
            case symbol_type::object: return "object";
            case symbol_type::func: return "func";
            case symbol_type::section: return "section";
            case symbol_type::file: return "file";
        }
        return "notype";
    }

    DebugInfo::DebugInfo(std::string program_name) : m_program_name{std::move(program_name)} {
        unique_fd fd{open(m_program_name.c_str(), O_RDONLY)};
        if (fd.get() < 0) {
            throw std::system_error(errno, std::generic_category(), "open");
        }

        auto loader = elf::create_mmap_loader(fd.get());
        (void) fd.release();
        m_elf = elf::elf{loader};
        m_dwarf = dwarf::dwarf{dwarf::elf::create_loader(m_elf)};
    }

    bool DebugInfo::is_dynamic() const {
        return m_elf.get_hdr().type == elf::et::dyn;
    }

    dwarf::die DebugInfo::function_from_pc(DwarfAddress program_counter) const {
        for (auto& cu : m_dwarf.compilation_units()) {
            if (!die_pc_range(cu.root()).contains(program_counter.value)) {
                continue;
            }

            for (const auto& die : cu.root()) {
                if (die.tag == dwarf::DW_TAG::subprogram && die_pc_range(die).contains(program_counter.value)) {
                    return die;
                }
            }
        }

        throw std::out_of_range("Cannot find function");
    }

    dwarf::line_table::iterator DebugInfo::line_entry_from_pc(DwarfAddress program_counter) const {
        for (auto& cu : m_dwarf.compilation_units()) {
            if (!die_pc_range(cu.root()).contains(program_counter.value)) {
                continue;
            }

            auto& line_table = cu.get_line_table();
            auto it = line_table.find_address(program_counter.value);
            if (it != line_table.end()) {
                return it;
            }
        }

        throw std::out_of_range{"Cannot find line entry"};
    }

    std::optional<SourceLocation> DebugInfo::source_location(DwarfAddress program_counter) const {
        try {
            auto line_entry = line_entry_from_pc(program_counter);
            return SourceLocation{line_entry->file->path, line_entry->line};
        } catch (const std::out_of_range&) {
            return std::nullopt;
        }
    }

    std::vector<DwarfAddress> DebugInfo::function_breakpoints(std::string_view name) const {
        std::vector<DwarfAddress> addresses;

        for (const auto& cu : m_dwarf.compilation_units()) {
            for (const auto& die : cu.root()) {
                if (!die.has(dwarf::DW_AT::name) || at_name(die) != name) {
                    continue;
                }

                auto entry = line_entry_from_pc(DwarfAddress{at_low_pc(die)});
                ++entry;
                addresses.push_back(DwarfAddress{entry->address});
            }
        }

        return addresses;
    }

    std::optional<DwarfAddress> DebugInfo::source_line_breakpoint(std::string_view file, unsigned line) const {
        for (const auto& compilation_unit : m_dwarf.compilation_units()) {
            const std::string unit_name = at_name(compilation_unit.root());
            if (!is_suffix(file, unit_name)) {
                continue;
            }

            const auto& line_table = compilation_unit.get_line_table();
            for (const auto& entry : line_table) {
                if (entry.is_stmt && entry.line == line) {
                    return DwarfAddress{entry.address};
                }
            }
        }

        return std::nullopt;
    }

    std::vector<Symbol> DebugInfo::lookup_symbol(std::string_view name) const {
        std::vector<Symbol> symbols;

        for (auto& section : m_elf.sections()) {
            auto type = section.get_hdr().type;
            if (type != elf::sht::symtab && type != elf::sht::dynsym) {
                continue;
            }

            for (auto symbol : section.as_symtab()) {
                if (symbol.get_name() != name) {
                    continue;
                }

                auto& data = symbol.get_data();
                symbols.push_back(Symbol{to_symbol_type(data.type()), symbol.get_name(), data.value});
            }
        }

        return symbols;
    }
}
