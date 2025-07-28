#include "heap.h"

// Heap base and heap limit
static block_header_t *heap_base = NULL;
static char *heap_limit = NULL;

// Initialize the heap
void init_heap(void *start, void *end)
{
    // Make the entire heap one large block
    heap_base = (block_header_t*)start;
    heap_base->size = (char*)end - (char*)start - HEAP_BLOCK_SIZE;  // Size
    heap_base->free = 1;            // Block is free
    heap_base->next = NULL;         // No previous or next yet
    heap_base->prev = NULL;
    heap_limit = (char*)end;        // Store the end address
}

// Allocate memory on the heap (First Fit)
void* kmalloc(size_t size)
{
    size = ALIGN4(size);    // Align the size to the closest 4 byte
    block_header_t *current = heap_base;

    // Look for a block thats big enough
    while(current)
    {
        if(current->free && current->size >= size)
        {
            // If the block is larger than what we need, split it.
            if(current->size > size + HEAP_BLOCK_SIZE)
            {
                block_header_t *new_block = (block_header_t*)((char*)current + HEAP_BLOCK_SIZE + size);
                new_block->size = current->size - size - HEAP_BLOCK_SIZE;
                new_block->free = 1;
                new_block->next = current->next;
                new_block->prev = current;

                if(new_block->next)
                {
                    new_block->next->prev = new_block;
                }

                current->next = new_block;
                current->size = size;
            }

            current->free = 0;      // Mark as unavailable
                                    
            // Return a pointer to the data
            return (char*)current + HEAP_BLOCK_SIZE;
        }

        current = current->next;
    }

    // If it ends up here, there is no more space
    return NULL;
}

// Free allocated block
void kfree(void *ptr)
{
    if(!ptr)
    {
        return;
    }

    // Get pointer to the block header
    block_header_t *block = (block_header_t*)((char*)ptr - HEAP_BLOCK_SIZE);
    block->free = 1;
    
    // Try to merge with the next block if it's free
    if(block->next && block->next->free)
    {
        block->size += HEAP_BLOCK_SIZE + block->next->size;
        block->next = block->next->next;

        if(block->next)
        {
            block->next->prev = block;
        }
    }

    // Attempt to merge with previous block if it's free
    if(block->prev && block->prev->free)
    {
        block->prev->size += HEAP_BLOCK_SIZE + block->size;
        block->prev->next = block->next;

        if(block->next)
        {
            block->next->prev = block->prev;
        }
    }
}
