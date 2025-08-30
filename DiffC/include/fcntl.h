#pragma once

#include <stdint.h>

typedef uint32_t mode_t; 

#define O_RDONLY   0x0000
#define O_WRONLY   0x0001
#define O_RDWR     0x0002
#define O_CREAT    0x0100
#define O_TRUNC    0x0200
#define O_APPEND   0x0400
#define O_NONBLOCK 0x0800
#define O_CLOEXEC  0x1000

// ----- fcntl() commands -----
#define F_DUPFD          0
#define F_GETFD          1
#define F_SETFD          2
#define F_GETFL          3
#define F_SETFL          4
#define F_GETLK          5
#define F_SETLK          6
#define F_SETLKW         7
#define F_DUPFD_CLOEXEC  1030 

#define FD_CLOEXEC 1

#define F_RDLCK 0
#define F_WRLCK 1
#define F_UNLCK 2

struct flock
{
    short    l_type;
    short    l_whence;   // SEEK_SET/SEEK_CUR/SEEK_END
    int32_t  l_start;    // Byte offset
    int32_t  l_len;      // 0 => to EOF
    int32_t  l_pid;      // Filled by kernel on F_GETLK
};

int open(const char *path, int oflag, ...);   // mode_t only used if O_CREAT
int creat(const char *path, mode_t mode);
int fcntl(int fd, int cmd, ...);

