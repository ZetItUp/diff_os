#include <stdint.h>
#include <stdio.h>
#include <system/threads.h>

#define STACK_SIZE 4096
#define THREAD_COUNT 20

static char g_stacks[THREAD_COUNT][STACK_SIZE];
static volatile int g_done[THREAD_COUNT];

// Simple worker: grabs an id, prints, sleeps briefly, marks done, exits.
static void thread_worker(void)
{
    int id = -1;
    // Infer which stack we're running on by checking the address of a local.
    uintptr_t sp = (uintptr_t)&id;
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        uintptr_t base = (uintptr_t)g_stacks[i];
        uintptr_t top = base + STACK_SIZE;
        if (sp >= base && sp < top)
        {
            id = i;
            break;
        }
    }

    printf("[thread %d] hello from worker\n", id);
    thread_sleep_ms(10);
    if (id >= 0 && id < THREAD_COUNT)
    {
        g_done[id] = 1;
    }
    thread_exit();
    for (;;)
        ;
}

static void *stack_top(int idx)
{
    uintptr_t top = (uintptr_t)g_stacks[idx] + STACK_SIZE;
    top &= ~(uintptr_t)0xF; // 16-byte align
    return (void *)top;
}

int main(void)
{
    printf("[main] spawning %d threads\n", THREAD_COUNT);

    int started = 0;
    for (int i = 0; i < THREAD_COUNT; ++i)
    {
        int tid = thread_create((void *)thread_worker, stack_top(i), STACK_SIZE);
        if (tid < 0)
        {
            printf("[main] thread_create failed for %d: %d\n", i, tid);
            continue;
        }
        started++;
    }

    // Wait for all threads to signal done
    while (1)
    {
        int done = 0;
        for (int i = 0; i < THREAD_COUNT; ++i)
        {
            if (g_done[i])
            {
                done++;
            }
        }

        if (done >= started)
        {
            break;
        }

        thread_yield();
    }

    printf("[main] all threads finished (started=%d)\n", started);
    return 0;
}
