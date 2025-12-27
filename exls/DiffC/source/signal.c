#include <signal.h>
#include <syscall.h>

__attribute__((noreturn)) void __signal_trampoline(void)
{
    void *frame = NULL;
    __asm__ __volatile__("mov 4(%%esp), %0" : "=r"(frame));
    system_signal_return(frame);

    for (;;)
    {
        __asm__ __volatile__("hlt");
    }
}

int signal(int sig, sighandler_t handler)
{
    return system_signal_set(sig, (void *)handler, (void *)__signal_trampoline);
}

int kill(int pid, int sig)
{
    return system_signal_send(pid, sig);
}

int raise(int sig)
{
    return system_signal_send(0, sig);
}

int sigsetmask(uint32_t mask)
{
    return system_signal_setmask(mask);
}

int siggetmask(uint32_t *mask)
{
    return system_signal_getmask(mask);
}
