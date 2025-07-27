#ifndef PAGING_H
#define PAGING_H

#include "stdint.h"

#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_SIZE       0x80        // Page Size (4 MB)
#define BLOCK_SIZE      0x400000    // 4MB
#define MAX_BLOCKS      64          // 256 MB RAM (64 * 4 MB) For now...

void init_paging();
int map_page(uint32_t virt_addr);
void unmap_page(uint32_t virt_addr);
int alloc_region(uint32_t virt_start, uint32_t size_mb);
int free_region(uint32_t virt_start, uint32_t size_mb);

#endif
