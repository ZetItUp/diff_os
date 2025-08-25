#include "paging.h"
#include "interfaces.h"
#include "stdio.h"

#ifndef KMAP_BASE
#define KMAP_BASE 0xD0000000u
#endif
#define KMAP_WINDOW_PAGES 1024u

static uint32_t kmap_cursor = 0;

void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags)
{
    if (size == 0) return (void*)0;

    const uint32_t page_sz = 0x1000u;

    uint32_t off       = phys & (page_sz - 1);
    uint32_t phys_page = phys & ~(page_sz - 1);
    uint32_t bytes     = ((size + off + page_sz - 1) & ~(page_sz - 1));
    uint32_t pages     = bytes / page_sz;

    if (pages > KMAP_WINDOW_PAGES) {
        // För stort för vårt fönster
        return (void*)0;
    }

    // Endast P|RW i kernel (ingen USER här, ignorera ev. användarflaggor)
    uint32_t f = (flags | PAGE_PRESENT | PAGE_RW) & (PAGE_PRESENT | PAGE_RW);

    // Välj start i fönstret, wrappa vid behov
    uint32_t start_idx = kmap_cursor;
    if (start_idx + pages > KMAP_WINDOW_PAGES)
        start_idx = 0;

    uint32_t va = KMAP_BASE + start_idx * page_sz;

    // Remappa (trampa över gamla) sida-för-sida
    uint32_t v = va;
    uint32_t p = phys_page;

    for (uint32_t i = 0; i < pages; i++, v += page_sz, p += page_sz)
    {
        // Se till att gammal mapping för den här VA är borta
        unmap_4kb_page(v);
        // Sätt ny mapping
        if (map_4kb_page_flags(v, p, f) != 0)
        {
            // Backa det vi hann mappa
            for (uint32_t j = 0; j < i; j++)
                unmap_4kb_page(va + j * page_sz);

            return (void*)0;
        }
    }

    // Flytta cursor och wrappa inom fönstret
    kmap_cursor = (start_idx + pages) % KMAP_WINDOW_PAGES;

    return (void*)(va + off);
}
