// All comments are written in English.
// Allman brace style is used consistently.

#include "system/usercopy.h"
#include "paging.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"

/* Declared/defined in your IRQ path (do NOT define here). */
extern volatile int g_in_irq;

/* We require a helper to inspect page tables. If your paging.c provides
 * paging_probe_pde_pte(va,&pde,&pte) -> 0 on success, use it. */
static int page_ok(uint32_t va, int need_write)
{
    uint32_t pde = 0;
    uint32_t pte = 0;

    /* Must be able to probe mapping */
    if (paging_probe_pde_pte(va, &pde, &pte) != 0)
    {
        return 0;
    }

    /* PDE present (bit 0) */
    if ((pde & 0x001u) == 0)
    {
        return 0;
    }

    /* PTE present + user; and RW if writing */
    if ((pte & 0x001u) == 0)
    {
        return 0;
    }
    if ((pte & 0x004u) == 0) /* PAGE_USER */
    {
        return 0;
    }
    if (need_write && (pte & 0x002u) == 0) /* PAGE_RW */
    {
        return 0;
    }

    return 1;
}

static int access_ok_region(uintptr_t start, size_t n, int need_write)
{
    uintptr_t end;
    uintptr_t p;

    if (n == 0)
    {
        return 1;
    }

    end = start + n - 1;
    if (end < start) /* overflow */
    {
        return 0;
    }

    /* Walk page-by-page */
    for (p = (start & ~0xFFFu); p <= (end & ~0xFFFu); p += 0x1000u)
    {
        if (!page_ok((uint32_t)p, need_write))
        {
            return 0;
        }
    }

    return 1;
}

int copy_from_user(void *kdst, const void *usrc, size_t n)
{
    uint8_t *kd;
    const uint8_t *us;
    size_t i;

    uintptr_t ra = (uintptr_t)__builtin_return_address(0);
#ifdef DIFF_DEBUG
    printf("[USERCOPY] in IRQ (from_user) caller=%p, src=%p, n=%zu\n", (void*)ra, usrc, n);
#endif
    
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

    /* For reads from user, PRESENT+USER is enough (no RW needed) */
    if (!access_ok_region((uintptr_t)usrc, n, 0))
    {
        return -1;
    }

    kd = (uint8_t *)kdst;
    us = (const uint8_t *)usrc;

    /* Bytewise copy avoids overrunning into an unmapped next page
       if the region is raced/changed between check and copy. */
    for (i = 0; i < n; i++)
    {
        kd[i] = us[i];
    }

    return 0;
}

int copy_to_user(void *udst, const void *ksrc, size_t n)
{
    const uint8_t *ks;
    uint8_t *ud;
    size_t i;

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

    /* For writes to user, require PRESENT+USER+RW */
    if (!access_ok_region((uintptr_t)udst, n, 1))
    {
        return -1;
    }

    ks = (const uint8_t *)ksrc;
    ud = (uint8_t *)udst;

    for (i = 0; i < n; i++)
    {
        ud[i] = ks[i];
    }

    return 0;
}

int copy_string_from_user(char *kdst, const char *usrc, size_t kdst_sz)
{
    size_t i;

    if (!kdst || !usrc || kdst_sz == 0)
    {
        return -1;
    }

    /* We copy byte-by-byte and validate each page before touching it. */
    i = 0;
    while (i + 1 < kdst_sz)
    {
        /* Validate one byte’s page for read */
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

    /* Ensure NUL termination even on truncation */
    kdst[kdst_sz - 1] = '\0';
    return 0;
}

