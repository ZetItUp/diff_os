#include <stdint.h>
#include <system/threads.h>
#include <syscall.h>

int thread_yield(void)
{
    system_thread_yield();
    return 0;
}

int thread_sleep_ms(uint32_t milliseconds)
{
    system_thread_sleep_ms(milliseconds);
    return 0;
}

int thread_get_id(void)
{
    return system_thread_get_id();
}

int thread_create(void *entry, void *user_stack_top, size_t kernel_stack_bytes)
{
    return do_sys(SYSTEM_THREAD_CREATE,
                  (int)(uintptr_t)entry,
                  (int)(uintptr_t)user_stack_top,
                  (int)kernel_stack_bytes,
                  0);
}

void thread_exit(void)
{
    (void)do_sys(SYSTEM_THREAD_EXIT, 0, 0, 0, 0);
    for (;;)
    {
        // Should never return; halt if syscall fails
        asm volatile("hlt");
    }
}
