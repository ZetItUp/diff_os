#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <system/threads.h>

static volatile int g_hits = 0;

static void on_signal(int sig)
{
    printf("[HANDLER] signal %d\n", sig);
    g_hits++;
}

int main(void)
{
    uint32_t mask = 0;

    printf("Signal Test Program\n");

    if (siggetmask(&mask) == 0)
    {
        printf("[INFO] initial mask = 0x%08x\n", (unsigned)mask);
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    printf("[TEST] raise SIGINT\n");
    raise(SIGINT);

    if (siggetmask(&mask) == 0)
    {
        uint32_t block = mask | (1u << SIGINT);
        printf("[TEST] block SIGINT (mask=0x%08x)\n", (unsigned)block);
        sigsetmask(block);
    }

    printf("[TEST] raise SIGINT while masked (should be deferred)\n");
    raise(SIGINT);

    if (siggetmask(&mask) == 0)
    {
        printf("[TEST] restore mask (mask=0x%08x)\n", (unsigned)mask);
        sigsetmask(mask & ~(1u << SIGINT));
    }

    printf("[TEST] raise SIGTERM\n");
    raise(SIGTERM);

    thread_sleep_ms(50);
    printf("[DONE] handler hits=%d\n", g_hits);
    return 0;
}
