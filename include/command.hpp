#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <variant>

#include "address.hpp"
#include "registers.hpp"

namespace dbg {
    struct NoopCommand {};
    struct ContinueCommand {};
    struct BreakAddressCommand { RuntimeAddress address; };
    struct BreakSourceCommand { std::string file; unsigned line = 0; };
    struct BreakFunctionCommand { std::string name; };
    struct RegisterDumpCommand {};
    struct RegisterReadCommand { Register reg; };
    struct RegisterWriteCommand { Register reg; std::uint64_t value = 0; };
    struct MemoryReadCommand { RuntimeAddress address; };
    struct MemoryWriteCommand { RuntimeAddress address; std::uint64_t value = 0; };
    struct ExitCommand {};
    struct StepInstructionCommand {};
    struct StepInCommand {};
    struct StepOverCommand {};
    struct StepOutCommand {};
    struct SymbolCommand { std::string name; };
    struct BacktraceCommand {};
    struct VariablesCommand {};

    using Command = std::variant<
            NoopCommand,
            ContinueCommand,
            BreakAddressCommand,
            BreakSourceCommand,
            BreakFunctionCommand,
            RegisterDumpCommand,
            RegisterReadCommand,
            RegisterWriteCommand,
            MemoryReadCommand,
            MemoryWriteCommand,
            ExitCommand,
            StepInstructionCommand,
            StepInCommand,
            StepOverCommand,
            StepOutCommand,
            SymbolCommand,
            BacktraceCommand,
            VariablesCommand
    >;

    struct ParseError {
        std::string message;
    };

    [[nodiscard]]
    std::expected<Command, ParseError> parse_command(std::string_view line);
}
