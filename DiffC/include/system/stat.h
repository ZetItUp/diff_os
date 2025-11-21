#pragma once

#include <stdint.h>

#ifndef _SYS_STAT_H
#define _SYS_STAT_H
#include <stddef.h>
#ifndef _MODE_T_DEFINED
typedef unsigned int mode_t;
#define _MODE_T_DEFINED
#endif
int mkdir(const char *path, mode_t mode);
int rmdir(const char *path);
#endif

typedef struct 
{
    uint32_t size;  // File size in bytes
} fs_stat_t;

int stat(const char *path, fs_stat_t *stat);
int fstat(int fd, fs_stat_t *stat);


