#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <syscall.h>

struct DIR 
{
    int handle; 
};

DIR* opendir(const char *path)
{
    if(!path)
    {
        return NULL;
    }

    int handle = system_open_dir(path);

    if(handle < 0)
    {
        return NULL;
    }

    DIR *d = (DIR*)malloc(sizeof(DIR));

    if(!d)
    {
        system_close_dir(handle);

        return NULL;
    }

    d->handle = handle;

    return d;
}

int readdir(DIR* dir_p, struct dirent *entry)
{
    if(!dir_p || !entry)
    {
        return -1;
    } 

    int read = system_read_dir(dir_p->handle, entry);

    return read;
}

int closedir(DIR* dir_p)
{
    if(!dir_p)
    {
        return -1;
    }

    int read = system_close_dir(dir_p->handle);
    free(dir_p);

    return read;
}
