#include <stdint.h>
#include <stdio.h>
#include <system/threads.h>
#include <time.h>

static void test_yield_burst(void)
{
    int tid = thread_get_id();
    printf("[TEST] yield burst, time=%d\n", tid);

    for (int i = 0; i < 5; i++)
    {
        printf("  yield %d\n", i);
        thread_yield();
    }
}

static void test_sleep_ms(uint32_t ms)
{
    uint64_t t0 = monotonic_ms();
    uint32_t t0_ms = (uint32_t)t0;

    printf("[TEST] msleep(%u) at %u ms\n", ms, t0_ms);

    (void)msleep(ms);

    uint64_t t1 = monotonic_ms();
    uint32_t t1_ms = (uint32_t)t1;
    uint32_t dt   = (uint32_t)(t1 - t0);

    printf("[TEST] woke at      %u ms  (+%u ms)\n", t1_ms, dt);
}

static void test_usleep(uint32_t us)
{
    uint64_t t0 = monotonic_ms();
    uint32_t t0_ms = (uint32_t)t0;

    printf("[TEST] usleep(%u) at %u ms\n", us, t0_ms);

    (void)usleep(us);

    uint64_t t1 = monotonic_ms();
    uint32_t t1_ms = (uint32_t)t1;
    uint32_t dt   = (uint32_t)(t1 - t0);

    printf("[TEST] woke at      %u ms  (~%u us, +%u ms)\n", t1_ms, us, dt);
}

static void test_nanosleep(uint32_t ms)
{
    struct timespec req;
    req.tv_sec  = ms / 1000u;
    req.tv_nsec = (long)((ms % 1000u) * 1000000u);

    uint64_t t0 = monotonic_ms();
    uint32_t t0_ms = (uint32_t)t0;

    printf("[TEST] nanosleep(%u ms) at %u ms\n", ms, t0_ms);

    (void)nanosleep(&req, NULL);

    uint64_t t1 = monotonic_ms();
    uint32_t t1_ms = (uint32_t)t1;
    uint32_t dt   = (uint32_t)(t1 - t0);

    printf("[TEST] woke at           %u ms  (+%u ms)\n", t1_ms, dt);
}

static void test_clock_gettime(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
    {
        printf("[TEST] clock_gettime: %u.%03u s\n",
               (unsigned)ts.tv_sec,
               (unsigned)(ts.tv_nsec / 1000000u));
    }
    else
    {
        printf("[TEST] clock_gettime failed\n");
    }
}

int main(void)
{
    printf("Thread and Timer Test Program\n");

    printf("Thread ID = %d\n", thread_get_id());
    test_clock_gettime();
    test_yield_burst();

    test_sleep_ms(100);
    test_sleep_ms(250);

    test_usleep(5000);
    test_usleep(20000);

    test_nanosleep(123);

    printf("[TEST] Completed!\n");
    return 0;
}

