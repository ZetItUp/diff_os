#pragma once

#include "stdint.h"

#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_SIZE       0x80                // Page Size (4 MB)
#define BLOCK_SIZE      0x400000            // 4MB
#define MAX_BLOCKS      1024

#define PAGE_SIZE_4KB   4096
#define PAGE_ENTRIES    1024                // 1024 * 4KB = 4MB per table
#define MAX_PHYS_PAGES (MAX_BLOCKS * (BLOCK_SIZE / PAGE_SIZE_4KB)) 

typedef struct {
    uint32_t base_low;
    uint32_t base_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;          // 1 = Usable RAM
    uint32_t acpi_ext;      // Extra flags
} __attribute__((packed)) e820_entry_t;

extern uint32_t page_directory[1024];

void init_paging(uint32_t ram_mb);
int map_page(uint32_t virt_addr, uint32_t size);
void unmap_page(uint32_t virt_addr);

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr);
void unmap_4kb_page(uint32_t virt_addr);

int alloc_region(uint32_t virt_start, uint32_t size_mb);
int free_region(uint32_t virt_start, uint32_t size_mb);

uint32_t alloc_phys_page();
void free_phys_page(uint32_t addr);

