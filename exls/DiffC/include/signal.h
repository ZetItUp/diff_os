#pragma once

#include <stdint.h>

typedef void (*sighandler_t)(int);

#define SIGINT   2
#define SIGILL   4
#define SIGABRT  6
#define SIGFPE   8
#define SIGKILL  9
#define SIGSEGV 11
#define SIGTERM 15

#define SIG_DFL ((sighandler_t)0)
#define SIG_IGN ((sighandler_t)1)

int signal(int sig, sighandler_t handler);
int kill(int pid, int sig);
int raise(int sig);
int sigsetmask(uint32_t mask);
int siggetmask(uint32_t *mask);
