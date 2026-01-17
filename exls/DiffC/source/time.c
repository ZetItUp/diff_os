#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <syscall.h>

// Shared kernel data page mapped by the kernel at process startup
// This allows reading time without a syscall
#define SHARED_KERNEL_DATA_VA 0x7FFE0000u

typedef struct shared_kernel_data
{
    volatile uint64_t time_ms;
    volatile uint32_t tick_count;
    volatile uint32_t timer_frequency;
} shared_kernel_data_t;

static volatile shared_kernel_data_t *kernel_data =
    (volatile shared_kernel_data_t *)SHARED_KERNEL_DATA_VA;

// Read time directly from shared page, no syscall needed
static inline uint64_t fast_time_ms(void)
{
    return kernel_data->time_ms;
}

// Fast conversion from ms to sec+usec using 32-bit division
// Works for ~49 days of uptime before overflow
static inline void ms_to_timeval(uint64_t ms, time_t *sec, suseconds_t *usec)
{
    uint32_t ms32 = (uint32_t)ms;
    *sec = (time_t)(ms32 / 1000u);
    *usec = (suseconds_t)((ms32 % 1000u) * 1000u);
}

static inline void ms_to_timespec(uint64_t ms, time_t *sec, long *nsec)
{
    uint32_t ms32 = (uint32_t)ms;
    *sec = (time_t)(ms32 / 1000u);
    *nsec = (long)((ms32 % 1000u) * 1000000u);
}

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

    ms_to_timespec(fast_time_ms(), &tp->tv_sec, &tp->tv_nsec);
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

    ms_to_timeval(fast_time_ms(), &tv->tv_sec, &tv->tv_usec);
    return 0;
}

uint64_t monotonic_ms(void)
{
    return fast_time_ms();
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

