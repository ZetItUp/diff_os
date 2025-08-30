// libc/sys/stat/mkdir.c
#include <errno.h>

#ifndef _MODE_T_DEFINED
typedef unsigned int mode_t;   // enkel fallback om du saknar mode_t
#define _MODE_T_DEFINED
#endif

// opendir/closedir finns redan i din userland via diffc.exl
extern int opendir(const char *path);
extern int closedir(int handle);

int mkdir(const char *path, mode_t mode)
{
    (void)mode;

    if (!path || !*path) {
        errno = EINVAL;
        return -1;
    }

    // Om katalogen redan finns: OK
    int h = opendir(path);
    if (h >= 0) {
        closedir(h);
        return 0;
    }

    // Saknar stöd för att skapa nya kataloger i det här FS:et
    errno = ENOSYS;
    return -1;
}

