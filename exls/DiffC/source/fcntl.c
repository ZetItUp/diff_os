// All comments are written in English.
// Allman brace style is used consistently.

#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <syscall.h>

// Open a file. If O_CREAT is set, read mode_t from varargs.
int open(const char *path, int oflag, ...)
{
    mode_t mode = 0;

    if (oflag & O_CREAT)
    {
        va_list ap;
        va_start(ap, oflag);
        mode = (mode_t)va_arg(ap, int); // default arg promotion
        va_end(ap);
    }

    int fd = system_open(path, oflag, (int)mode);

    return fd;
}

// Create a file (convenience wrapper).
int creat(const char *path, mode_t mode)
{
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
}

// File control. Minimal stub until kernel provides real support.
int fcntl(int fd, int cmd, ...)
{
    va_list ap;
    int arg = 0;

    switch (cmd)
    {
        case F_GETFD:
        {
            // No per-fd flags supported; return 0 (no FD_CLOEXEC).
            return 0;
        }

        case F_SETFD:
        {
            // Accept and ignore FD flags for now.
            va_start(ap, cmd);
            arg = va_arg(ap, int);
            va_end(ap);

            (void)arg;

            return 0;
        }

        case F_GETFL:
        {
            // No kernel getter; return 0 which equals O_RDONLY in your flags.
            return 0;
        }

        case F_SETFL:
        {
            // Accept and ignore (e.g., O_NONBLOCK) until you add kernel support.
            va_start(ap, cmd);
            arg = va_arg(ap, int);
            va_end(ap);

            (void)arg;

            return 0;
        }

        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
        {
            // Duplication is not supported yet.
            return -1;
        }

        case F_GETLK:
        case F_SETLK:
        case F_SETLKW:
        {
            // Advisory locking not supported yet.
            return -1;
        }

        default:
        {
            // Unknown command.
            return -1;
        }
    }
}

