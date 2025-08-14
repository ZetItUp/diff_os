#include "heap.h"
#include "stdio.h"
#include "string.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MIN_BLOCK_SIZE (sizeof(block_header_t) + ALIGNMENT)

block_header_t *heap_base = NULL;
char *heap_limit = NULL;

static int heap_validate(void)
{
    if(!heap_base)
    {
        return 0;
    }

    block_header_t *current = heap_base;
    size_t total_size = (char*)heap_limit - (char*)heap_base;
    size_t calculated_size = 0;

    while(current)
    {
        if(((size_t)current & (ALIGNMENT - 1)) != 0)
        {
            printf("Heap corruption: Misaligned block at %p\n", current);

            return 0;
        }

        if(current->size > (size_t)(heap_limit - (char*)current))
        {
            printf("Heap corruption: Invalid size %zu at %p\n", current->size, current);

            return 0;
        }

        if(current->next && current->next->prev != current)
        {
            printf("Heap corruption: Broken link at %p\n", current);

            return 0;
        }

        calculated_size += HEAP_BLOCK_SIZE + current->size;
        current = current->next;

        if(calculated_size > total_size * 2)
        {
            printf("Heap corruption: Infinite loop detected\n");

            return 0;
        }
    }

    return 1;
}

void init_heap(void *start, void *end)
{
    if(!start || !end || end <= start)
    {
        printf("ERROR: Invalid heap range %p-%p\n", start, end);

        return;
    }

    size_t heap_size = (char*)end - (char*)start;

    if(heap_size < MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE)
    {
        printf("ERROR: Heap too small (%zu bytes), need at least %zu\n",
               heap_size, MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE);

        return;
    }

    heap_base = (block_header_t*)start;
    heap_base->size = heap_size - HEAP_BLOCK_SIZE;
    heap_base->free = 1;
    heap_base->next = NULL;
    heap_base->prev = NULL;
    heap_limit = (char*)end;
}

void* kmalloc(size_t size)
{
    if(size == 0)
    {
        printf("[KMALLOC] WARNING: Zero-size allocation\n");

        return NULL;
    }

    if(!heap_base)
    {
        printf("[KMALLOC] ERROR: Heap not initialized\n");

        return NULL;
    }

    size_t aligned_size = ALIGN(size);
    size_t total_needed = aligned_size + HEAP_BLOCK_SIZE;

    block_header_t *current = heap_base;
    block_header_t *best_fit = NULL;
    size_t best_fit_size = 0;

    while(current)
    {
        if(current->free)
        {
            if(current->size >= aligned_size)
            {
                if(current->size == aligned_size)
                {
                    best_fit = current;

                    break;
                }

                if(!best_fit || current->size < best_fit_size)
                {
                    best_fit = current;
                    best_fit_size = current->size;
                }
            }
        }

        current = current->next;
    }

    if(!best_fit)
    {
        printf("[KMALLOC] ERROR: Out of memory for %zu bytes (%zu aligned)\n",
               size, aligned_size);

        return NULL;
    }

    if(best_fit->size >= total_needed + MIN_BLOCK_SIZE)
    {
        size_t remaining_size = best_fit->size - total_needed;

        block_header_t *new_block = (block_header_t*)((char*)best_fit + total_needed);
        new_block->size = remaining_size;
        new_block->free = 1;
        new_block->next = best_fit->next;
        new_block->prev = best_fit;

        if(best_fit->next)
        {
            best_fit->next->prev = new_block;
        }

        best_fit->next = new_block;
        best_fit->size = aligned_size;
        best_fit->free = 0;
    }
    else
    {
        best_fit->free = 0;
    }

    return (char*)best_fit + HEAP_BLOCK_SIZE;
}

void kfree(void *ptr)
{
    if(!ptr)
    {
        printf("[KFREE] WARNING: Null pointer free\n");

        return;
    }

    if(!heap_base)
    {
        printf("[KFREE] ERROR: Heap not initialized\n");

        return;
    }

    if(ptr < (void*)((char*)heap_base + HEAP_BLOCK_SIZE) || ptr >= (void*)heap_limit)
    {
        printf("[KFREE] ERROR: Pointer %p outside heap range\n", ptr);

        return;
    }

    block_header_t *block = (block_header_t*)((char*)ptr - HEAP_BLOCK_SIZE);

    if(block->free)
    {
        printf("[KFREE] ERROR: Double free at %p\n", ptr);

        return;
    }

    block->free = 1;

    if(block->next && block->next->free)
    {
        block->size += HEAP_BLOCK_SIZE + block->next->size;
        block->next = block->next->next;

        if(block->next)
        {
            block->next->prev = block;
        }
    }

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

void heap_dump(void)
{
    if(!heap_base)
    {
        printf("[HEAP DUMP] Heap not initialized\n");

        return;
    }

    if(!heap_validate())
    {
        printf("[HEAP DUMP] WARNING: Heap corruption detected!\n");
    }

    printf("\n--- HEAP DUMP (%p-%p) ---\n", heap_base, heap_limit);

    block_header_t *current = heap_base;
    size_t total_used = 0;
    size_t total_free = 0;
    int block_count = 0;

    while(current)
    {
        printf("Block %d: %p size=%zu %s",
               block_count++, current, current->size,
               current->free ? "(free)" : "(used)");

        if(current->prev)
        {
            printf(" prev=%p", current->prev);
        }

        if(current->next)
        {
            printf(" next=%p", current->next);
        }

        printf("\n");

        if(current->free)
        {
            total_free += current->size;
        }
        else
        {
            total_used += current->size;
        }

        current = current->next;
    }

    size_t total_space = (char*)heap_limit - (char*)heap_base;
    size_t overhead = total_space - total_used - total_free;

    int used_pct = (total_space != 0) ? (int)((total_used * 100) / total_space) : 0;
    int free_pct = (total_space != 0) ? (int)((total_free * 100) / total_space) : 0;
    int over_pct = (total_space != 0) ? (int)((overhead   * 100) / total_space) : 0;

    printf("\nSUMMARY:\n");
    printf("Total heap space: %zu bytes\n", total_space);
    printf("Used: %zu bytes (%d)\n", total_used, used_pct);
    printf("Free: %zu bytes (%d)\n", total_free, free_pct);
    printf("Overhead: %zu bytes (%d)\n", overhead, over_pct);
    printf("--- END DUMP ---\n\n");
}

