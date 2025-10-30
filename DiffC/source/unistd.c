#include <unistd.h>
#include <syscall.h>
#include <stdlib.h>

int exec_dex(const char *path, int argc, char **argv)
{
    return system_exec_dex(path, argc, argv);
}

int close(int fd)
{
    return system_close(fd);
}

ssize_t read(int fd, void *buf, size_t count)
{
    if (!buf || count == 0) return 0;
    return (ssize_t)system_read(fd, buf, (unsigned long)count);
}

ssize_t write(int fd, const void *buf, size_t count)
{
    if (!buf || count == 0) return 0;
    return (ssize_t)system_write(fd, buf, (unsigned long)count);
}

off_t lseek(int fd, off_t offset, int whence)
{
    return (off_t)system_lseek(fd, (long)offset, whence);
}

void __stack_chk_fail(void)
{
    printf("[DiffC] Stack protector failed!\n");
    exit(127);
}

