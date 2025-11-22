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

