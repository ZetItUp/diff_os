#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Types

typedef int clockid_t;

typedef int64_t time_t;
typedef int64_t suseconds_t;

struct timespec
{
    time_t tv_sec;
    long tv_nsec;
};

struct timeval
{
    time_t tv_sec;
    suseconds_t tv_usec;
};

// Clocks

#define CLOCK_REALTIME   0
#define CLOCK_MONOTONIC  1

// API

int clock_gettime(clockid_t clock_id, struct timespec* tp);
int nanosleep(const struct timespec* req, struct timespec* rem);
int gettimeofday(struct timeval* tv);

// Convenience

uint64_t monotonic_ms(void);
int msleep(uint32_t ms);
int usleep(uint32_t usec);
unsigned sleep(unsigned seconds);

#ifdef __cplusplus
}
#endif

