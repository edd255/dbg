# dbg
A mini x86 debugger for Linux. Created by [Sy Brand](https://github.com/TartanLlama). I follow his tutorial in this repo.

## Overview
So far, the debugger is able to execute binaries, set breakpoints, and inspect registers and memory. The basis of the debugger is the `ptrace` system call. Citing the man page:

> The `ptrace()` system call provides a means by which one process (the "tracer") may observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers. It is primarily used to implement breakpoint debugging and system call tracing.

Usually, you set up `ptrace` the following way:
* Fork a process.
* The child calls `ptrace(PTRACE_TRACEME, 0, 0, 0);`
* The parent calls `ptrace(PTRACE_ATTACK, child_pid, 0, 0)`

The parent now controls the child. The system calls offers a ton of actions that can be executed using requests à la `PTRACE_foo`.

The next thing debuggers usually support are breakpoints which can be implemented using interrupts. Operating systems provide `interrupt` handling for debuggers, which is encoded as the single-byte instruction `0xCC`. Basically, an interrupt is a request for the processor to halt. The idea here is to replace the instruction at a specific instruction with `0xCC`. If we want to execute our original instruction again, the `interrupt` handler restores the original byte, and eventually manipulates the `rip` register to continue at the original position.

## TODO
- [ ] Documentation
- [ ] Technical overview of the features
- [ ] Using a package manager
- [ ] Using a sane build system
