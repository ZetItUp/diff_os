#include <stdint.h>

#define PAGE_PRESENT        0x1
#define PAGE_RW             0x2
#define PAGE_PS             0x80    // Page Size (1 == 2MB)

// Place the physical address static for now
__attribute__((section(".page_tables")))
__attribute__((aligned(4096)))
uint64_t pml4[512];

__attribute__((section(".page_tables")))
__attribute__((aligned(4096)))
static uint64_t pdpt[512];

__attribute__((section(".page_tables")))
__attribute__((aligned(4096)))
static uint64_t pd[512];

void init_paging()
{
    // Link tables
    pml4[0] = (uint64_t)pdpt | PAGE_PRESENT | PAGE_RW;
    pdpt[0] = (uint64_t)pd | PAGE_PRESENT | PAGE_RW;

    // Map 0x00000000–0x200000 to a 2 MB page (huge page)
    pd[0] = 0x00000000 | PAGE_PRESENT | PAGE_RW | PAGE_PS;
}
