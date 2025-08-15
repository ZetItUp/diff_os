#pragma once

#include "stddef.h"
#include "stdint.h"

#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_USER       0x4
#define PAGE_PWT        0x8
#define PAGE_PCD        0x10

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

// Debug helpers
void paging_dump_range(uint32_t addr, uint32_t size);
int  paging_check_user_range(uint32_t addr, uint32_t size);
void hexdump_bytes(const void *addr, size_t n);
void dump_pde_pte(uint32_t lin);
int page_present(uint32_t lin);
void dump_err_bits(uint32_t err);

void init_paging(uint32_t ram_mb);
int map_page(uint32_t virt_addr, uint32_t size);
void unmap_page(uint32_t virt_addr);

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr);
int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags);
void unmap_4kb_page(uint32_t virt_addr);

int alloc_region(uint32_t virt_start, uint32_t size_mb);
int free_region(uint32_t virt_start, uint32_t size_mb);

uint32_t alloc_phys_page();
void free_phys_page(uint32_t addr);

void paging_flush_tlb();
void ufree(void *ptr, size_t size);
void* umalloc(size_t size);
void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask);
void paging_set_user(uint32_t addr, uint32_t size);
