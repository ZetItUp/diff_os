#include "system/usercopy.h"
#include "paging.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"

extern volatile int g_in_irq;

// Quick check if VA is readable/writable from user space right now?
static int page_ok(uint32_t va, int need_write)
{
    uint32_t pde = 0;
    uint32_t pte = 0;

    // Must be able to probe the mapping
    if (paging_probe_pde_pte(va, &pde, &pte) != 0)
    {
        return 0;
    }

    // PDE must be present
    if ((pde & 0x001u) == 0)
    {
        return 0;
    }

    // PTE must be present, user and RW if we want to write
    if ((pte & 0x001u) == 0)
    {
        return 0;
    }

    if ((pte & 0x004u) == 0) // PAGE_USER
    {
        return 0;
    }

    if (need_write && (pte & 0x002u) == 0) // PAGE_RW
    {
        return 0;
    }

    return 1;
}

// Validate a user range page-by-page
static int access_ok_region(uintptr_t start, size_t n, int need_write)
{
    uintptr_t end;
    uintptr_t p;

    if (n == 0)
    {
        return 1;
    }

    end = start + n - 1;

    // Bail on wrap-around
    if (end < start)
    {
        return 0;
    }

    // Go over each page to avoid touching unmapped areas 
    for (p = (start & ~0xFFFu); p <= (end & ~0xFFFu); p += 0x1000u)
    {
        if (!page_ok((uint32_t)p, need_write))
        {
            return 0;
        }
    }

    return 1;
}

// Copy bytes from user to kernel safely
int copy_from_user(void *kdst, const void *usrc, size_t n)
{
    uint8_t *kd;
    const uint8_t *us;
    size_t i;

#ifdef DIFF_DEBUG
    // Debug so we can see who called and how much
    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
    printf("[USERCOPY] from_user ra=%p src=%p n=%zu irq=%d\n", (void*)ra, usrc, n, (int)g_in_irq);
#endif

    // Never touch user memory from IRQ
    if (g_in_irq)
    {
        return -1;
    }

    if (!kdst || !usrc)
    {
        return -1;
    }

    if (n == 0)
    {
        return 0;
    }

    // Reads only need PRESENT+USER
    if (!access_ok_region((uintptr_t)usrc, n, 0))
    {
        return -1;
    }

    kd = (uint8_t*)kdst;
    us = (const uint8_t*)usrc;

    // Byte-wise to avoid stepping past a valid page boundary during races
    for (i = 0; i < n; i++)
    {
        kd[i] = us[i];
    }

    return 0;
}

// Copy bytes from kernel to user safely
int copy_to_user(void *udst, const void *ksrc, size_t n)
{
    const uint8_t *ks;
    uint8_t *ud;
    size_t i;

    // Never write into user memory from IRQ
    if (g_in_irq)
    {
        return -1;
    }

    if (!udst || !ksrc)
    {
        return -1;
    }

    if (n == 0)
    {
        return 0;
    }

    // Writes need PRESENT+USER+RW
    if (!access_ok_region((uintptr_t)udst, n, 1))
    {
        return -1;
    }

    ks = (const uint8_t*)ksrc;
    ud = (uint8_t*)udst;

    for (i = 0; i < n; i++)
    {
        ud[i] = ks[i];
    }

    return 0;
}

// Copy string from user
int copy_string_from_user(char *kdst, const char *usrc, size_t kdst_sz)
{
    size_t i;

    if (!kdst || !usrc || kdst_sz == 0)
    {
        return -1;
    }

    // Validate the page before each read
    i = 0;

    while (i + 1 < kdst_sz)
    {
        // Check current byte’s page for read
        if (!access_ok_region((uintptr_t)(usrc + i), 1, 0))
        {
            return -1;
        }

        kdst[i] = usrc[i];

        if (kdst[i] == '\0')
        {
            return 0;
        }

        i++;
    }

    // Force NUL at the end
    kdst[kdst_sz - 1] = '\0';

    return 0;
}

