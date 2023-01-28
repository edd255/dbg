#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include "debugger.hpp"

void execute_debugee(const std::string& program)
{
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        std::cerr << "Error in ptrace\n";
        return;
    }
    execl(program.c_str(), program.c_str(), nullptr);
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cerr << "Program name not specified";
        return -1;
    }
    const std::string usage =
        "Debugger -- Version 0.0.1\n"
        "Commands:\n"
        "\t continue:\t             Step over breakpoint\n"
        "\t break <addr>:\t\t     Set breakpoint at <addr>\n"
        "\t register\n"
        "\t\t dump:               Print register values\n"
        "\t\t read <reg:          Print value at register <reg>\n"
        "\t\t write <reg> <val:   Write <val> to register <reg>\n"
        "\t memory\n"
        "\t\t read <addr>:        Read value at address <addr>\n"
        "\t\t write <addr> <val>: Write <val> at address <addr>\n"
    ;
    std::cout << usage;
    auto program = argv[1];
    auto pid = fork();
    if (pid == 0) {
        // we're in the child process
        // execute debugee
        personality(ADDR_NO_RANDOMIZE);
        execute_debugee(program);
    } else if (pid >= 1) {
        // we're in the parent process
        // execute debugger
        std::cout << "Starting debugging process " << pid << '\n';
        Debugger dbg(program, pid);
        dbg.run();
    }
}
