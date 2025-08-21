#include "paging.h"
#include "interfaces.h"
#include "stdio.h"

#ifndef KMAP_BASE
#define KMAP_BASE 0xD0000000u
#endif

static uint32_t kmap_next = KMAP_BASE;

void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags)
{
    // If size is zero, nothing to map
    if (size == 0)
    {
        return (void*)0;
    }

    uint32_t page_sz = 0x1000u;

    // Offset inside the first physical page
    uint32_t off = phys & (page_sz - 1);

    // Align physical address down to page boundary
    uint32_t phys_page = phys & ~(page_sz - 1);

    // Round up to whole pages (covering offset + size)
    uint32_t bytes = ((size + off + page_sz - 1) & ~(page_sz - 1));

    // Pick next free virtual address and align up to page boundary
    uint32_t va = (kmap_next + (page_sz - 1)) & ~(page_sz - 1);

    uint32_t v = va;
    uint32_t p = phys_page;

    // Only keep the present/rw/user bits from flags
    uint32_t f = (flags | PAGE_PRESENT | PAGE_RW) & (PAGE_PRESENT | PAGE_RW | PAGE_USER);

    // Map each page one by one
    for (uint32_t i = 0; i < bytes; i += page_sz, v += page_sz, p += page_sz)
    {
        if (map_4kb_page_flags(v, p, f) != 0)
        {
            // Roll back already mapped pages if something fails
            for (uint32_t j = 0; j < i; j += page_sz)
            {
                unmap_4kb_page(va + j);
            }

            return (void*)0;
        }
    }

    // Bump the next free virtual mapping base
    kmap_next = va + bytes;

    // Return the mapped virtual address plus original offset
    return (void*)(va + off);
}

