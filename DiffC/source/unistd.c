#include <unistd.h>
#include <syscall.h>

int exec_dex(const char *path, int argc, char **argv)
{
    return system_exec_dex(path, argc, argv);
}
