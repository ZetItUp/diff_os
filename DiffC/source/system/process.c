#include <system/process.h>

int process_spawn(const char *path, int argc, char **argv)
{
    return system_process_spawn(path, argc, argv);
}

void process_exit(int code)
{
    system_exit(code);
} 

int process_wait(int pid, int *status)
{
    return system_wait_pid(pid, status);
}
