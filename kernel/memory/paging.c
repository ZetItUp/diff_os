#include <stdint.h>

#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_SIZE_4MB   0x80

__attribute__((section(".lowmem")))
__attribute__((aligned(4096)))
uint32_t page_directory[1024];

void init_paging()
{
    // Map 4MB (en stor page, enkel identity)
    page_directory[0] = 0x00000000 | PAGE_PRESENT | PAGE_RW | PAGE_SIZE_4MB;

    // Ladda page directoryn
    asm volatile(
        "mov %0, %%cr3\n"           // Ladda CR3
        "mov %%cr4, %%eax\n"
        "or $0x10, %%eax\n"         // Sätt PSE (Page Size Extension)
        "mov %%eax, %%cr4\n"
        "mov %%cr0, %%eax\n"
        "or $0x80000000, %%eax\n"   // Sätt PG-bit
        "mov %%eax, %%cr0\n"
        :
        : "r"(page_directory)
        : "eax"
    );
}

