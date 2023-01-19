#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include "debugger.h"

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
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl(program, program, nullptr);
    } else if (pid >= 1) {
        // we're in the parent process
        // execute debugger
        std::cout << "Starting debugging process " << pid << '\n';
        Debugger dbg(program, pid);
        dbg.run();
    }
}
