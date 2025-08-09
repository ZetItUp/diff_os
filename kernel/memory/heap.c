#include "heap.h"
#include "stdio.h"
#include "string.h"

#define ALIGNMENT 4  // Use 8-byte alignment for modern systems
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
#define MIN_BLOCK_SIZE (sizeof(block_header_t) + ALIGNMENT) // Min usable block (header + min data)

block_header_t *heap_base = NULL;
char *heap_limit = NULL;

// Heap validation function
static int heap_validate() {
    if (!heap_base) return 0;
    
    block_header_t *current = heap_base;
    size_t total_size = (char*)heap_limit - (char*)heap_base;
    size_t calculated_size = 0;
    
    while (current) {
        // Check block alignment
        if (((size_t)current & (ALIGNMENT-1))) {
            printf("Heap corruption: Misaligned block at %p\n", current);
            return 0;
        }
        
        // Check size validity
        if (current->size > (size_t)(heap_limit - (char*)current)) {
            printf("Heap corruption: Invalid size %zu at %p\n", current->size, current);
            return 0;
        }
        
        // Check chain integrity
        if (current->next && current->next->prev != current) {
            printf("Heap corruption: Broken link at %p\n", current);
            return 0;
        }
        
        calculated_size += HEAP_BLOCK_SIZE + current->size;
        current = current->next;
        
        // Prevent infinite loops
        if (calculated_size > total_size * 2) {
            printf("Heap corruption: Infinite loop detected\n");
            return 0;
        }
    }
    
    return 1;
}

void init_heap(void *start, void *end) {
    // Validate input parameters
    if (!start || !end || end <= start) {
        printf("ERROR: Invalid heap range %p-%p\n", start, end);
        return;
    }

    // Ensure the heap is large enough
    size_t heap_size = (char*)end - (char*)start;
    if (heap_size < MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE) {
        printf("ERROR: Heap too small (%zu bytes), need at least %zu\n", 
              heap_size, MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE);
        return;
    }

    // Initialize the heap
    heap_base = (block_header_t*)start;
    heap_base->size = heap_size - HEAP_BLOCK_SIZE;
    heap_base->free = 1;
    heap_base->next = NULL;
    heap_base->prev = NULL;
    heap_limit = (char*)end;

    //printf("Heap initialized: %p-%p (%zu bytes)\n", start, end, heap_size);
}

void* kmalloc(size_t size) {
    // Validate input
    if (size == 0) {
        printf("[KMALLOC] WARNING: Zero-size allocation\n");
        return NULL;
    }

    if (!heap_base) {
        printf("[KMALLOC] ERROR: Heap not initialized\n");
        return NULL;
    }

    // Calculate aligned size including header
    size_t aligned_size = ALIGN(size);
    size_t total_needed = aligned_size + HEAP_BLOCK_SIZE;

    // Find best fit block
    block_header_t *current = heap_base;
    block_header_t *best_fit = NULL;
    size_t best_fit_size = 0;

    while (current) {
        if (current->free) {
            // Check if block is large enough
            if (current->size >= aligned_size) {
                // Prefer blocks that can be split perfectly
                if (current->size == aligned_size) {
                    best_fit = current;
                    break;
                }
                // Otherwise track the best fit
                if (!best_fit || current->size < best_fit_size) {
                    best_fit = current;
                    best_fit_size = current->size;
                }
            }
        }
        current = current->next;
    }

    if (!best_fit) {
        printf("[KMALLOC] ERROR: Out of memory for %zu bytes (%zu aligned)\n", 
               size, aligned_size);
        //heap_dump();
        return NULL;
    }

    // Check if we can split the block
    if (best_fit->size >= total_needed + MIN_BLOCK_SIZE) {
        // Calculate remaining space after allocation
        size_t remaining_size = best_fit->size - total_needed;
        
        // Create new free block in the remaining space
        block_header_t *new_block = (block_header_t*)((char*)best_fit + total_needed);
        new_block->size = remaining_size;
        new_block->free = 1;
        new_block->next = best_fit->next;
        new_block->prev = best_fit;
        
        // Update surrounding blocks
        if (best_fit->next) {
            best_fit->next->prev = new_block;
        }
        best_fit->next = new_block;
        
        // Update current block
        best_fit->size = aligned_size;
        best_fit->free = 0;
        
        //printf("[KMALLOC] Allocated %zu bytes at %p (split, remaining %zu)\n", aligned_size, best_fit, remaining_size);
    } else {
        // Use entire block
        best_fit->free = 0;
        //printf("[KMALLOC] Allocated %zu bytes at %p (exact fit, block was %zu)\n", aligned_size, best_fit, best_fit->size);
    }

    // Return pointer to data area
    return (char*)best_fit + HEAP_BLOCK_SIZE;
}

void kfree(void *ptr) {
    // Validate input
    if (!ptr) {
        printf("[KFREE] WARNING: Null pointer free\n");
        return;
    }

    if (!heap_base) {
        printf("[KFREE] ERROR: Heap not initialized\n");
        return;
    }

    // Check pointer is within heap bounds
    if (ptr < (void*)((char*)heap_base + HEAP_BLOCK_SIZE) || ptr >= (void*)heap_limit) {
        printf("[KFREE] ERROR: Pointer %p outside heap range\n", ptr);
        return;
    }

    // Get block header
    block_header_t *block = (block_header_t*)((char*)ptr - HEAP_BLOCK_SIZE);
    
    // Check for double free
    if (block->free) {
        printf("[KFREE] ERROR: Double free at %p\n", ptr);
        return;
    }

    // Mark as free
    block->free = 1;
    //printf("[KFREE] Freed block at %p (size %zu)\n", block, block->size);

    // Merge with next block if free
    if (block->next && block->next->free) {
        //printf("[KFREE] Merging with next block %p (size %zu)\n", block->next, block->next->size);
        
        block->size += HEAP_BLOCK_SIZE + block->next->size;
        block->next = block->next->next;
        
        if (block->next) {
            block->next->prev = block;
        }
    }

    // Merge with previous block if free
    if (block->prev && block->prev->free) {
        //printf("[KFREE] Merging with previous block %p (size %zu)\n", block->prev, block->prev->size);
        
        block->prev->size += HEAP_BLOCK_SIZE + block->size;
        block->prev->next = block->next;
        
        if (block->next) {
            block->next->prev = block->prev;
        }
    }
}

void heap_dump() {
    if (!heap_base) {
        printf("[HEAP DUMP] Heap not initialized\n");
        return;
    }

    if (!heap_validate()) {
        printf("[HEAP DUMP] WARNING: Heap corruption detected!\n");
    }

    printf("\n--- HEAP DUMP (%p-%p) ---\n", heap_base, heap_limit);
    
    block_header_t *current = heap_base;
    size_t total_used = 0, total_free = 0;
    int block_count = 0;

    while (current) {
        printf("Block %d: %p size=%zu %s", 
               block_count++, current, current->size,
               current->free ? "(free)" : "(used)");
        
        if (current->prev) printf(" prev=%p", current->prev);
        if (current->next) printf(" next=%p", current->next);
        printf("\n");
        
        if (current->free) total_free += current->size;
        else total_used += current->size;
        
        current = current->next;
    }

    size_t total_space = (char*)heap_limit - (char*)heap_base;
    size_t overhead = total_space - total_used - total_free;
    
    printf("\nSUMMARY:\n");
    printf("Total heap space: %zu bytes\n", total_space);
    printf("Used: %zu bytes (%d)\n", total_used, (int)(total_used/total_space*100));
    printf("Free: %zu bytes (%d)\n", total_free, (int)(total_free/total_space*100));
    printf("Overhead: %zu bytes (%d)\n", overhead, (int)(overhead/total_space*100));
    printf("--- END DUMP ---\n\n");
}
