#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/personality.h>
#include "debugger.h"

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
