#include "stdio.h"
#include "stdint.h"
#include "paging.h"

// Align to 4KB
__attribute__((aligned(4096))) uint32_t page_directory[1024];

// Page table pool
// (4 tables = 16 MB, expand if needed)
__attribute__((aligned(4096))) uint32_t kernel_page_tables[4][PAGE_ENTRIES];

static uint32_t *block_bitmap;
static uint32_t max_blocks;                     // Number of 4MB blocks (RAM / 4)
static uint32_t phys_page_bitmap[(MAX_PHYS_PAGES + 31) / 32];

static inline void flush_tlb()
{
    asm volatile("mov %%cr3, %%eax; mov %%eax, %%cr3" ::: "eax", "memory");
}

static inline void set_phys_page(int i)
{
    phys_page_bitmap[i / 32] |= (1 << (i % 32));
}

static inline void clear_phys_page(int i)
{
    phys_page_bitmap[i / 32] &= ~(1 << (i % 32));
}

static inline int test_phys_page(int i)
{
    return phys_page_bitmap[i / 32] & (1 << (i % 32));
}

// Helper methods for Bitmapping
static inline int test_block(int i)
{
    return block_bitmap[i / 32] & (1 << (i % 32));
}

static inline void set_block(int i)
{
    block_bitmap[i / 32] |= (1 << (i % 32));
}

static inline void clear_block(int i)
{
    block_bitmap[i / 32] &= ~(1 << (i % 32));
}

// Find first available (4 MB) block
static int find_free_block()
{
    for(int i = 0; i < MAX_BLOCKS; i++)
    {
        if(!test_block(i))
        {
            return i;
        }
    }

    // If we are here, we are out of memory
    return -1;
}

// Allocate a page table
static void alloc_page_table(uint32_t dir_index, uint32_t *table)
{
    // Zero the page table
    for(int i = 0; i < PAGE_ENTRIES; i++)
    {
        table[i] = 0;
    }

    // Add table to directory
    page_directory[dir_index] = ((uint32_t)table & 0xFFFFF000) | PAGE_PRESENT | PAGE_RW;
}

// Initialize bitmap
static void init_phys_bitmap()
{
    for(int i = 0; i < (MAX_PHYS_PAGES + 31) / 32; i++)
    {
        phys_page_bitmap[i] = 0;
    }

    // Reserve first 4MB (kernel + identity map)
    for(int i = 0; i < (BLOCK_SIZE / PAGE_SIZE_4KB); i++)
    {
        set_phys_page(i);
    }
}

void init_paging(uint32_t ram_mb)
{
    // Calculated number of blocks
    max_blocks = ram_mb / 4;

    // Limit to 4GB
    if(max_blocks > MAX_BLOCKS)
    {
        max_blocks = MAX_BLOCKS;
    }

    static uint32_t bitmap_storage[(MAX_BLOCKS + 31) / 32];
    block_bitmap = bitmap_storage;

    // Reset page directory and bitmap
    for(int i = 0; i < 1024; i++)
    {
        page_directory[i] = 0;
    }  

    for(int i = 0; i < (int)((max_blocks + 31) / 32); i++)
    {
        block_bitmap[i] = 0;
    }

    init_phys_bitmap();

    // Early identity map
    alloc_page_table(0, kernel_page_tables[0]);

    for(int i = 0; i < 1024; i++)
    {
        kernel_page_tables[0][i] = (i * 0x1000) | PAGE_PRESENT | PAGE_RW;
    }

    set_block(0);       // Mark first block as unavailable

    // Load CR3 with the address of the page directory
    asm volatile("mov %0, %%cr3" :: "r"(&page_directory));

    // Activate PSE in CR4
    uint32_t cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x10;    // Bit 4 = PSE
    asm volatile("mov %0, %%cr4" :: "r"(cr4));

    // Set CR0.PG (Bit 31)
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

// Map a page
int map_page(uint32_t virt_addr, uint32_t size)
{
    // If size is atleast 4MB and the address is aligned
    if(size >= BLOCK_SIZE && (virt_addr % BLOCK_SIZE == 0))
    {
        int blocks = size / BLOCK_SIZE;

        for(int i = 0; i < blocks; i++)
        {
            int block = find_free_block();

            if(block < 0)
            {
                return -2;
            }

            uint32_t phys_addr = block * BLOCK_SIZE;

            page_directory[(virt_addr >> 22) + i] = phys_addr | PAGE_PRESENT | PAGE_RW | PAGE_SIZE;
            set_block(block);
        }   
    }
    else
    {
        // Map with 4KB pages
        uint32_t pages = (size + PAGE_SIZE_4KB - 1) / PAGE_SIZE_4KB;

        for(uint32_t i = 0; i < pages; i++)
        {
            uint32_t phys_addr = alloc_phys_page();

            if(!phys_addr)
            {
                return -3;
            }

            map_4kb_page(virt_addr + (i * PAGE_SIZE_4KB), phys_addr);
        }
    }

    // Flush table for just this address
    flush_tlb();
    
    // We good!
    return 0;
}

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr) 
{
    uint32_t dir_index = virt_addr >> 22;               // Top 10 bits
    uint32_t table_index = (virt_addr >> 12) & 0x3FF;   // Middle 10 bits

    uint32_t *table;

    // If page directory entry is not present, create table
    if (!(page_directory[dir_index] & PAGE_PRESENT)) 
    {
        static int next_table = 0;
        
        if (next_table >= 4) 
        {
            return -1; // Out of static tables
        }

        table = kernel_page_tables[next_table++];
        alloc_page_table(dir_index, table);
    } 
    else 
    {
        table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000);
    }

    // Set page table entry
    table[table_index] = (phys_addr & 0xFFFFF000) | PAGE_PRESENT | PAGE_RW;

    // Flush TLB for this address
    asm volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");

    return 0;
}

void unmap_4kb_page(uint32_t virt_addr) 
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FF;

    if(!(page_directory[dir_index] & PAGE_PRESENT))
    {
        return;
    }

    uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000);
    table[table_index] = 0;

    asm volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");
}

// Unmap a page
void unmap_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;               // Top 10 bits
    uint32_t table_index = (virt_addr >> 12) & 0x3FF;   // Middle 10 bits
    uint32_t entry = page_directory[dir_index];

    if(!(entry & PAGE_PRESENT))
    {
        return;
    }

    if(entry & PAGE_SIZE)
    {
        // 4MB Page
        uint32_t phys_addr = entry & 0xFFC00000;
        int block = phys_addr / BLOCK_SIZE;

        free_phys_page(phys_addr);
        clear_block(block);
        page_directory[dir_index] = 0;
    }
    else
    {
        // 4KB Page
        uint32_t *page_table = (uint32_t*)(entry & 0xFFFFF000);
        uint32_t pte = page_table[table_index];

        if(pte & PAGE_PRESENT)
        {
            free_phys_page(pte & 0xFFFFF000);
            // Add free phys page
            page_table[table_index] = 0;
        }

        // Check if table is empty
        int empty = 1;

        for(int i = 0; i < 1024; i++)
        {
            if(page_table[i] & PAGE_PRESENT)
            {
                empty = 0;
                break;
            }
        }

        if(empty)
        {
            page_directory[dir_index] = 0;
            // If table was allocated dynamic, free page table
        }
    }

    // Flush the table
    flush_tlb();
}

// Allocate a region of 4MB blocks
int alloc_region(uint32_t virt_start, uint32_t size_mb)
{
    if(virt_start % BLOCK_SIZE != 0)
    {
        // Virtuell address not aligned
        return -1;
    }

    // Calculate number of blocks needed, ex. 6MB = 2 blocks
    int blocks = (size_mb + 3) / 4;

    for(int i = 0; i < blocks; i++)
    {
        uint32_t virt_addr = virt_start + (i * BLOCK_SIZE);
        int res = map_page(virt_addr, BLOCK_SIZE);

        if(res != 0)
        {
            // If we fail, roll back everything that was mapped
            for(int j = 0; j < i; j++)
            {
                uint32_t undo_addr = virt_start + (j * BLOCK_SIZE);
                unmap_page(undo_addr);
            }

            return res;
        }   
    }

    flush_tlb();

    // OK
    return 0;
}

int free_region(uint32_t virt_start, uint32_t size_mb)
{
    if((virt_start % BLOCK_SIZE) != 0)
    {
        // Virtual address not aligned
        return -1;
    } 

    int blocks = (size_mb + 3) / 4;

    for(int i = 0; i < blocks; i++)
    {
        uint32_t virt_addr = virt_start + (i * BLOCK_SIZE);
        unmap_page(virt_addr);
    }
    
    flush_tlb();

    // OK
    return 0;
}

uint32_t alloc_phys_page()
{
    for(int i = 0; i < MAX_PHYS_PAGES; i++)
    {
        if(!test_phys_page(i))
        {
            set_phys_page(i);

            return i * PAGE_SIZE_4KB;   // Physical Address
        }
    }


    return 0;   // Out of memory
}

void free_phys_page(uint32_t addr)
{
    int index = addr / PAGE_SIZE_4KB;

    if(index < MAX_PHYS_PAGES)
    {
        clear_phys_page(index);
    }
}
