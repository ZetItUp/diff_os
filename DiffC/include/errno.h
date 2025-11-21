#pragma once

int *__errno_location(void);

#define errno (*__errno_location())

#define EPERM        1
#define ENOENT       2
#define EIO          5
#define E2BIG        7
#define ENOMEM      12
#define EACCES      13
#define EFAULT      14
#define EBUSY       16
#define EEXIST      17
#define EXDEV       18
#define ENODEV      19
#define ENOTDIR     20
#define EISDIR      21
#define EINVAL      22
#define ENFILE      23
#define EMFILE      24
#define ENOSPC      28
#define ERANGE      34
#define ENOSYS      38
#define ENOTEMPTY   39
