#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <syscall.h>

static inline void split_sleep_ms(uint64_t ms)
{
    while (ms > 0)
    {
        uint32_t chunk = (ms > (uint64_t)0xFFFFFFFFu) ? 0xFFFFFFFFu : (uint32_t)ms;
        if (chunk == 0)
        {
            break;
        }
        system_thread_sleep_ms(chunk);
        ms -= (uint64_t)chunk;
    }
}

int clock_gettime(clockid_t clock_id, struct timespec* tp)
{
    if (!tp)
    {
        return -1;
    }

    if (clock_id != CLOCK_MONOTONIC && clock_id != CLOCK_REALTIME)
    {
        return -1;
    }

    uint64_t ms = system_time_ms();
    tp->tv_sec = (time_t)(ms / 1000ull);
    tp->tv_nsec = (long)((ms % 1000ull) * 1000000ull);
    return 0;
}

int nanosleep(const struct timespec* req, struct timespec* rem)
{
    if (!req || req->tv_sec < 0 || req->tv_nsec < 0 || req->tv_nsec >= 1000000000L)
    {
        if (rem)
        {
            rem->tv_sec = 0;
            rem->tv_nsec = 0;
        }
        return -1;
    }

    if (req->tv_sec == 0 && req->tv_nsec == 0)
    {
        system_thread_yield();
        if (rem)
        {
            rem->tv_sec = 0;
            rem->tv_nsec = 0;
        }
        return 0;
    }

    uint64_t ms = (uint64_t)req->tv_sec * 1000ull + (uint64_t)(req->tv_nsec / 1000000L);
    if ((req->tv_nsec % 1000000L) != 0)
    {
        ms += 1ull;
    }

    split_sleep_ms(ms);

    if (rem)
    {
        rem->tv_sec = 0;
        rem->tv_nsec = 0;
    }
    return 0;
}

int gettimeofday(struct timeval* tv)
{
    if (!tv)
    {
        return -1;
    }

    uint64_t ms = system_time_ms();
    tv->tv_sec = (time_t)(ms / 1000ull);
    tv->tv_usec = (suseconds_t)((ms % 1000ull) * 1000ull);
    return 0;
}

uint64_t monotonic_ms(void)
{
    return system_time_ms();
}

int msleep(uint32_t ms)
{
    if (ms == 0)
    {
        system_thread_yield();
        return 0;
    }
    split_sleep_ms((uint64_t)ms);
    return 0;
}

int usleep(uint32_t usec)
{
    if (usec == 0)
    {
        system_thread_yield();
        return 0;
    }

    uint64_t ms = (uint64_t)(usec / 1000u);
    if ((usec % 1000u) != 0)
    {
        ms += 1ull;
    }
    split_sleep_ms(ms);
    return 0;
}

unsigned sleep(unsigned seconds)
{
    split_sleep_ms((uint64_t)seconds * 1000ull);
    return 0;
}

