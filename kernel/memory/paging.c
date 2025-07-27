#include "stdint.h"
#include "paging.h"

// Align to 4KB
__attribute__((aligned(4096))) uint32_t page_directory[1024];

// Bitmap for a 4MB Block
static uint32_t *block_bitmap;
static uint32_t max_blocks;         // Number of 4MB blocks (RAM / 4)

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

    // Identity map for the first 4MB (Kernel space)
    page_directory[0] = 0x00000000 | PAGE_PRESENT | PAGE_RW | PAGE_SIZE;
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

int map_page(uint32_t virt_addr)
{
    // Index in Page Directory (every entry covers 4MB)
    uint32_t index = virt_addr >> 22;   // Directory Index, High 10 bits
                                        
    if(index >= 1024)
    {
        // Invalid virtual address
        return -1;
    }

    int block = find_free_block();
    if(block < 0)
    {
        // Out of physical memory
        return -2;
    }

    uint32_t phys_addr = block * BLOCK_SIZE;    

    // Set PDE: [physical base address] + flags
    page_directory[index] = phys_addr | PAGE_PRESENT | PAGE_RW | PAGE_SIZE;
    set_block(block);

    // Flush table for just this address
    asm volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");

    // We good!
    return 0;
}

void unmap_page(uint32_t virt_addr)
{
    uint32_t index = virt_addr >> 22;

    if(index >= 1024)
    {
        return;
    }

    uint32_t entry = page_directory[index];
    if(!(entry & PAGE_PRESENT))
    {
        return;
    }

    // Get physical address, aligned
    uint32_t phys_addr = entry & 0xFFC00000;
    int block = phys_addr / BLOCK_SIZE;

    clear_block(block);
    page_directory[index] = 0;  // Remove the entry
                                
    // Flust the table
    asm volatile("invlpg (%0)" :: "r"(virt_addr) : "memory");
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
        int res = map_page(virt_addr);

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
    
    // OK
    return 0;
}




