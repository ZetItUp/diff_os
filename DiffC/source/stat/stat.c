#include <system/stat.h>
#include <syscall.h>

int stat(const char *path, fs_stat_t *stat)
{
    if(!path || !stat)
    {
        return -1;
    }

    fs_stat_t fstat;

    int r = system_file_stat(path, &fstat);

    if(r != 0)
    {
        return -1;
    }

    stat->size = fstat.size;

    return 0;
}

int fstat(int fd, fs_stat_t *stat)
{
    if(fd < 0 || !stat)
    {
        return -1;
    }

    fs_stat_t fstat;

    int r = system_file_fstat(fd, &fstat);

    if(r != 0)
    {
        return -1;
    }

    stat->size = fstat.size;

    return 0;
}
