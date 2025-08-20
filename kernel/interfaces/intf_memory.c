#include "paging.h"
#include "interfaces.h"
#include "stdio.h"

#ifndef KMAP_BASE
#define KMAP_BASE 0xD0000000u
#endif

static uint32_t kmap_next = KMAP_BASE;

void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags)
{
    if (size == 0)
    {
        return (void*)0;
    }

    uint32_t page_sz = 0x1000u;
    uint32_t off = phys & (page_sz - 1);
    uint32_t phys_page = phys & ~(page_sz - 1);
    uint32_t bytes = ((size + off + page_sz - 1) & ~(page_sz - 1));

    uint32_t va = (kmap_next + (page_sz - 1)) & ~(page_sz - 1);
    uint32_t v = va;
    uint32_t p = phys_page;

    uint32_t f = (flags | PAGE_PRESENT | PAGE_RW) & (PAGE_PRESENT | PAGE_RW | PAGE_USER);

    for (uint32_t i = 0; i < bytes; i += page_sz, v += page_sz, p += page_sz)
    {
        if (map_4kb_page_flags(v, p, f) != 0)
        {
            for (uint32_t j = 0; j < i; j += page_sz)
            {
                unmap_4kb_page(va + j);
            }

            return (void*)0;
        }
    }

    kmap_next = va + bytes;

    return (void*)(va + off);
}
