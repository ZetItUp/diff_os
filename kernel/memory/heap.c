#include "heap.h"
#include "stdio.h"

#define MIN_BLOCK_SIZE (HEAP_BLOCK_SIZE + 8)  // Minsta tillåtna blockstorlek

block_header_t *heap_base = 0;
char *heap_limit = 0;

void init_heap(void *start, void *end) {
    if (start == 0 || end == 0 || end <= start) {
        printf("ERROR: Invalid heap range\n");
        return;
    }

    heap_base = (block_header_t*)start;
    heap_base->size = (char*)end - (char*)start - HEAP_BLOCK_SIZE;
    heap_base->free = 1;
    heap_base->next = 0;
    heap_base->prev = 0;
    heap_limit = (char*)end;
}

void* kmalloc(size_t size) {
    if (size == 0 || !heap_base) return 0;
    
    size = ALIGN4(size);
    block_header_t *current = heap_base;

    // First-fit search
    while (current) {
        if (current->free) {
            // Exakt match eller tillräckligt med plats för att splitta
            if (current->size >= size) {
                size_t remaining = current->size - size;
                
                // Kontrollera om vi kan splitta blocket
                if (remaining >= MIN_BLOCK_SIZE) {
                    block_header_t *new_block = (block_header_t*)((char*)current + HEAP_BLOCK_SIZE + size);
                    
                    new_block->size = remaining - HEAP_BLOCK_SIZE;
                    new_block->free = 1;
                    new_block->next = current->next;
                    new_block->prev = current;
                    
                    if (current->next) {
                        current->next->prev = new_block;
                    }
                    
                    current->next = new_block;
                    current->size = size;
                }
                
                current->free = 0;
                return (char*)current + HEAP_BLOCK_SIZE;
            }
        }
        current = current->next;
    }
    
    return 0;  // Ingen lämplig block hittades
}

void kfree(void *ptr) {
    if (!ptr || !heap_base) return;

    block_header_t *block = (block_header_t*)((char*)ptr - HEAP_BLOCK_SIZE);
    block->free = 1;

    // Sammanfoga med nästa block om det är fritt
    if (block->next && block->next->free) {
        block->size += HEAP_BLOCK_SIZE + block->next->size;
        block->next = block->next->next;
        if (block->next) {
            block->next->prev = block;
        }
    }

    // Sammanfoga med föregående block om det är fritt
    if (block->prev && block->prev->free) {
        block->prev->size += HEAP_BLOCK_SIZE + block->size;
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block->prev;
        }
    }
}

void heap_dump() {
    if (!heap_base) {
        printf("Heap not initialized\n");
        return;
    }

    block_header_t *current = heap_base;
    int total_used = 0;
    int total_free = 0;
    
    printf("--- HEAP DUMP ---\n");
    while (current) {
        printf("Block %x: size=%d, free=%d\n", 
              (unsigned)current, (int)current->size, current->free);
        
        if (current->free) total_free += current->size;
        else total_used += current->size;
        
        current = current->next;
    }
    printf("Total: used=%d, free=%d\n", total_used, total_free);
}
