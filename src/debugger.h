#include <iostream>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <vector>
#include <sstream>
#include "../libs/linenoise.h"

class Debugger
{
    private:
        std::string program_name;
        pid_t pid;

    public:
        Debugger(std::string program_name, pid_t pid) : 
            program_name{std::move(program_name)}, pid{pid} {}

        void run()
        {
            int wait_status;
            auto options = 0;
            waitpid(pid, &wait_status, options);
            char* line = nullptr;
            while ((line = linenoise("> ")) != nullptr) {
                handle_command(line);
                linenoiseHistoryAdd(line);
                linenoiseFree(line);
            }
        }

        void handle_command(const std::string& line)
        {
            auto args = split(line, ' ');
            auto command = args[0];

            if (is_prefix(command, "continue")) {
                continue_execution();
            } else {
                std::cerr << "Unknown command\n";
            }
        }

        std::vector<std::string> split(const std::string& s, char delimiter)
        {
            std::vector<std::string> out{};
            std::stringstream ss {s};
            std::string item;
            while (std::getline(ss, item, delimiter)) {
                out.push_back(item);
            }
            return out;
        }

        bool is_prefix(const std::string& s, const std::string& of)
        {
            if (s.size() > of.size()) {
                return false;
            }

            return std::equal(s.begin(), s.end(), of.begin());
        }

        void continue_execution()
        {
            ptrace(PTRACE_CONT, pid, nullptr, nullptr);
            int wait_status;
            auto options = 0;
            waitpid(pid, &wait_status, options);
        }

};
