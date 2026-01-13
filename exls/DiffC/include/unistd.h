#pragma once

#include <syscall.h>
#include <stddef.h>
#include <stdint.h>

typedef int ssize_t;
typedef int32_t off_t;

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

int close(int fd);
ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
off_t lseek(int fd, off_t offset, int whence);
ssize_t readlink(const char *path, char *buf, size_t bufsize);
int unlink(const char *path);
int exec_dex(const char *path, int argc, char **argv);
int spawn_process(const char *path, int argc, char **argv);
int chdir(const char *path);
char *getcwd(char *buf, size_t size);

void *sbrk(intptr_t incr);
int brk(void *addr);


void __stack_chk_fail(void);
