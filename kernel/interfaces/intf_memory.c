#include "paging.h"
#include "interfaces.h"
#include "stdio.h"

#ifndef KMAP_BASE
#define KMAP_BASE 0xD0000000u
#endif

#define KMAP_WINDOW_PAGES 1024u

static uint32_t kmap_cursor = 0;

static uintptr_t s_user_heap_base = 0x40000000u;   // Default fallback
static uintptr_t s_user_heap_end  = 0x40000000u;   // Current break
static uintptr_t s_user_heap_max  = 0x44000000u;   // Default 64 MB window

static inline uintptr_t page_down(uintptr_t x)
{
    return x & ~(PAGE_SIZE - 1u);
}

static inline uintptr_t page_up(uintptr_t x)
{
    return (x + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
}

void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags)
{
    if (size == 0) return (void*)0;

    const uint32_t page_sz = 0x1000u;

    uint32_t off = phys & (page_sz - 1u);
    uint32_t phys_page = phys & ~(page_sz - 1u);
    uint32_t bytes = ((size + off + page_sz - 1u) & ~(page_sz - 1u));
    uint32_t pages = bytes / page_sz;

    if (pages > KMAP_WINDOW_PAGES)
    {
        return (void*)0;
    }

    // Kernel mapping: force P|RW, drop USER
    uint32_t f = (flags | PAGE_PRESENT | PAGE_RW) & (PAGE_PRESENT | PAGE_RW);

    uint32_t start_idx = kmap_cursor;
    if (start_idx + pages > KMAP_WINDOW_PAGES)
    {
        start_idx = 0;
    }

    uint32_t va = KMAP_BASE + start_idx * page_sz;

    uint32_t v = va;
    uint32_t p = phys_page;

    for (uint32_t i = 0; i < pages; i++, v += page_sz, p += page_sz)
    {
        unmap_4kb_page(v);

        if (map_4kb_page_flags(v, p, f) != 0)
        {
            for (uint32_t j = 0; j < i; j++)
            {
                unmap_4kb_page(va + j * page_sz);
            }

            return (void*)0;
        }
    }

    kmap_cursor = (start_idx + pages) % KMAP_WINDOW_PAGES;

    return (void*)(va + off);
}
int system_brk_set(void *new_break)
{
    if (!new_break)
    {
        return (int)s_user_heap_end;
    }

    uintptr_t req = (uintptr_t)new_break;

    // Do not move below heap base
    if (req < s_user_heap_base)
    {
        return (int)s_user_heap_end;
    }

    // Do not exceed the fixed heap window
    if (req > s_user_heap_max)
    {
        return -1;
    }

    uintptr_t end = page_up(req);
    uintptr_t old_end = s_user_heap_end;

    s_user_heap_end = end;           // Move the break
    // NOTE: Do NOT change s_user_heap_max here — window stays fixed.

    // Reserve newly grown range so demand paging will commit pages
    if (end > old_end)
    {
        paging_reserve_range(old_end, end - old_end);
    }

    // Ensure page tables exist across the whole heap window (4MB steps)
    uintptr_t start4m = s_user_heap_base & ~((uintptr_t)0x400000u - 1u);
    uintptr_t end4m   = (s_user_heap_max + 0x3FFFFFu) & ~((uintptr_t)0x400000u - 1u);

    for (uintptr_t va = start4m; va < end4m; va += 0x400000u)
    {
        (void)paging_ensure_pagetable((uint32_t)va, PAGE_USER | PAGE_RW);
    }

    return (int)s_user_heap_end;
}

void system_brk_init_window(uintptr_t heap_base, uintptr_t heap_size)
{
    // Interpret parameters as HEAP base/size (not image base/size)
    uintptr_t base = page_up(heap_base);
    uintptr_t max  = base + heap_size;

    s_user_heap_base = base;
    s_user_heap_end  = base;
    s_user_heap_max  = max;

    // Pre-create page tables for the whole heap window (4MB steps)
    uintptr_t start4m = base & ~((uintptr_t)0x400000u - 1u);
    uintptr_t end4m   = (max + 0x3FFFFFu) & ~((uintptr_t)0x400000u - 1u);

    for (uintptr_t va = start4m; va < end4m; va += 0x400000u)
    {
        (void)paging_ensure_pagetable((uint32_t)va, PAGE_USER | PAGE_RW);
    }

    // Mark the entire heap window as demand-paged
    (void)paging_reserve_range(base, max - base);
}

