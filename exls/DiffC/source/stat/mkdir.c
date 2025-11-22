// libc/sys/stat/mkdir.c
#include <system/stat.h>
#include <errno.h>
#include <syscall.h>

int mkdir(const char *path, mode_t mode)
{
    (void)mode;

    if (!path || !*path)
    {
        errno = EINVAL;
        return -1;
    }

    int rc = system_mkdir(path);
    if (rc == 0)
    {
        return 0;
    }

    if (rc == -2)
    {
        errno = EEXIST;
    }
    else
    {
        errno = ENOENT;
    }

    return -1;
}

int rmdir(const char *path)
{
    if (!path || !*path)
    {
        errno = EINVAL;
        return -1;
    }

    int rc = system_rmdir(path);
    if (rc == 0)
    {
        return 0;
    }

    if (rc == -2)
    {
        errno = ENOTEMPTY;
    }
    else if (rc == -3)
    {
        errno = ENOTDIR;
    }
    else
    {
        errno = ENOENT;
    }

    return -1;
}
