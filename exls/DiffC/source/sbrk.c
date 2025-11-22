#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <syscall.h>

static void *s_current_brk_cached = 0;

static void __sbrk_init_if_needed(void)
{
    if (!s_current_brk_cached)
    {
        s_current_brk_cached = system_brk(NULL);
    }
}

void *sbrk(intptr_t incr)
{
    __sbrk_init_if_needed();

    void *old = s_current_brk_cached;
    uintptr_t want = (uintptr_t)old + (uintptr_t)incr;

    void *res = system_brk((void*)want);

    if (res == (void*)-1 || res == NULL)
    {
        return (void*)-1;
    }

    s_current_brk_cached = res;

    return old; // POSIX: return previous break on success
}

int brk(void *addr)
{
    __sbrk_init_if_needed();

    void *res = system_brk(addr);

    if (res == (void*)-1 || res == NULL)
    {
        return -1;
    }

    s_current_brk_cached = res;

    return 0;
}

