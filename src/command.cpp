#include "../include/command.hpp"

#include <charconv>
#include <expected>
#include <format>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace dbg {
    namespace {
        [[nodiscard]]
        std::unexpected<ParseError> parse_error(std::string message)
        {
            return std::unexpected(ParseError{std::move(message)});
        }

        [[nodiscard]]
        std::vector<std::string> split_words(std::string_view line)
        {
            std::istringstream stream{std::string{line}};
            std::vector<std::string> words;
            std::string word;

            while (stream >> word) {
                words.push_back(word);
            }

            return words;
        }

        [[nodiscard]]
        std::expected<std::uint64_t, ParseError> parse_unsigned(
                std::string_view text,
                int base,
                std::string_view description
        )
        {
            if (base == 16 && text.starts_with("0x")) {
                text.remove_prefix(2);
            }

            if (text.empty()) {
                return parse_error(std::format("Missing {}", description));
            }

            std::uint64_t value = 0;
            auto begin = text.data();
            auto end = text.data() + text.size();
            auto [ptr, ec] = std::from_chars(begin, end, value, base);
            if (ec != std::errc{} || ptr != end) {
                return parse_error(std::format("Invalid {}", description));
            }

            return value;
        }

        [[nodiscard]]
        std::expected<unsigned, ParseError> parse_line_number(std::string_view text)
        {
            auto value = parse_unsigned(text, 10, "line number");
            if (!value) {
                return std::unexpected(value.error());
            }

            if (*value > std::numeric_limits<unsigned>::max()) {
                return parse_error("Line number is too large");
            }

            return static_cast<unsigned>(*value);
        }
    }

    std::expected<Command, ParseError> parse_command(std::string_view line)
    {
        auto args = split_words(line);
        if (args.empty()) {
            return Command{NoopCommand{}};
        }

        const auto& command = args[0];

        if (command == "continue") {
            return Command{ContinueCommand{}};
        }

        if (command == "break") {
            if (args.size() < 2) {
                return parse_error("Usage: break <addr|file:line|function>");
            }

            const auto& target = args[1];
            if (target.starts_with("0x")) {
                auto address = parse_unsigned(target, 16, "address");
                if (!address) {
                    return std::unexpected(address.error());
                }
                return Command{BreakAddressCommand{RuntimeAddress{*address}}};
            }

            if (auto separator = target.find(':'); separator != std::string::npos) {
                auto file = target.substr(0, separator);
                auto line_text = std::string_view{target}.substr(separator + 1);
                if (file.empty() || line_text.empty()) {
                    return parse_error("Usage: break <file>:<line>");
                }

                auto line_number = parse_line_number(line_text);
                if (!line_number) {
                    return std::unexpected(line_number.error());
                }

                return Command{BreakSourceCommand{std::move(file), *line_number}};
            }

            return Command{BreakFunctionCommand{target}};
        }

        if (command == "register") {
            if (args.size() < 2) {
                return parse_error("Usage: register <dump|read|write>");
            }

            if (args[1] == "dump") {
                return Command{RegisterDumpCommand{}};
            }

            if (args[1] == "read") {
                if (args.size() < 3) {
                    return parse_error("Usage: register read <reg>");
                }

                auto reg = find_register_from_name(args[2]);
                if (!reg) {
                    return parse_error("Unknown register name");
                }

                return Command{RegisterReadCommand{*reg}};
            }

            if (args[1] == "write") {
                if (args.size() < 4) {
                    return parse_error("Usage: register write <reg> <val>");
                }

                auto reg = find_register_from_name(args[2]);
                if (!reg) {
                    return parse_error("Unknown register name");
                }

                auto value = parse_unsigned(args[3], 16, "register value");
                if (!value) {
                    return std::unexpected(value.error());
                }

                return Command{RegisterWriteCommand{*reg, *value}};
            }

            return parse_error("Unknown register command");
        }

        if (command == "memory") {
            if (args.size() < 3) {
                return parse_error("Usage: memory <read|write> <addr> [val]");
            }

            auto address = parse_unsigned(args[2], 16, "address");
            if (!address) {
                return std::unexpected(address.error());
            }

            if (args[1] == "read") {
                return Command{MemoryReadCommand{RuntimeAddress{*address}}};
            }

            if (args[1] == "write") {
                if (args.size() < 4) {
                    return parse_error("Usage: memory write <addr> <val>");
                }

                auto value = parse_unsigned(args[3], 16, "memory value");
                if (!value) {
                    return std::unexpected(value.error());
                }

                return Command{MemoryWriteCommand{RuntimeAddress{*address}, *value}};
            }

            return parse_error("Unknown memory command");
        }

        if (command == "exit") {
            return Command{ExitCommand{}};
        }
        if (command == "stepi") {
            return Command{StepInstructionCommand{}};
        }
        if (command == "step") {
            return Command{StepInCommand{}};
        }
        if (command == "next") {
            return Command{StepOverCommand{}};
        }
        if (command == "finish") {
            return Command{StepOutCommand{}};
        }
        if (command == "symbol") {
            if (args.size() < 2) {
                return parse_error("Usage: symbol <name>");
            }
            return Command{SymbolCommand{args[1]}};
        }
        if (command == "backtrace") {
            return Command{BacktraceCommand{}};
        }
        if (command == "variables") {
            return Command{VariablesCommand{}};
        }

        return parse_error("Unknown command");
    }
}
