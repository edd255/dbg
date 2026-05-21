#include "../include/debugger.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <print>
#include <string>
#include <string_view>
#include <sys/personality.h>
#include <sys/ptrace.h>
#include <unistd.h>

namespace {
    constexpr std::string_view usage =
        "Debugger -- Version 0.0.1\n"
        "Commands:\n"
        "\t continue:             Continue execution\n"
        "\t break <addr>:         Set breakpoint at <addr>\n"
        "\t break <file>:<line>:  Set breakpoint at source line\n"
        "\t break <function>:     Set breakpoint at function\n"
        "\t stepi:                Step one instruction\n"
        "\t step:                 Step into\n"
        "\t next:                 Step over\n"
        "\t finish:               Step out\n"
        "\t symbol <name>:        Lookup symbol\n"
        "\t backtrace:            Print backtrace\n"
        "\t variables:            Print local variables\n"
        "\t exit:                 Exit debugger\n"
        "\t register\n"
        "\t\t dump:               Print register values\n"
        "\t\t read <reg>:         Print value at register <reg>\n"
        "\t\t write <reg> <val>:  Write <val> to register <reg>\n"
        "\t memory\n"
        "\t\t read <addr>:        Read value at address <addr>\n"
        "\t\t write <addr> <val>: Write <val> at address <addr>\n";

    [[noreturn]] 
    void execute_debugee(const std::string& program) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            std::println(stderr, "Error in ptrace: {}", std::strerror(errno));
            _exit(1);
        }

        execl(program.c_str(), program.c_str(), nullptr);
        std::println(stderr, "Error in execl: {}", std::strerror(errno));
        _exit(1);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::println(stderr, "Program name not specified");
        return -1;
    }

    const std::string program = argv[1];
    std::print("{}", usage);
    std::fflush(stdout);

    auto pid = fork();
    if (pid == 0) {
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(program);
    }

    if (pid > 0) {
        std::println("Starting debugging process {}", pid);
        dbg::Debugger debugger{program, pid};
        debugger.run();
        return 0;
    }

    std::println(stderr, "Error in fork: {}", std::strerror(errno));
    return -1;
}
