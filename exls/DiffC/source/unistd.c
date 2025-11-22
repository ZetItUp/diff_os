#include <unistd.h>
#include <syscall.h>

int exec_dex(const char *path, int argc, char **argv)
{
    return system_exec_dex(path, argc, argv);
}

int chdir(const char *path)
{
    return system_chdir(path);
}

char *getcwd(char *buf, size_t size)
{
    if (!buf || size == 0)
    {
        return NULL;
    }

    if (system_getcwd(buf, size) < 0)
    {
        return NULL;
    }

    return buf;
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
