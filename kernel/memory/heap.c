#include "heap.h"
#include "stdio.h"
#include "string.h"
#include "stdint.h"

#define ALIGNMENT 8
#define ALIGN(n) (((n) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

// Heap state
block_header_t* heap_base = NULL;
char* heap_limit = NULL;

// Fix heap if the first block looks broken
static void heap_repair_if_broken(void)
{
    if (!heap_base || !heap_limit)
    {
        return;
    }

    if ((char*)heap_base + HEAP_BLOCK_SIZE > heap_limit)
    {
        return;
    }

    int broken = 0;

    if (heap_base->size == 0)
    {
        broken = 1;
    }

    if ((char*)heap_base + HEAP_BLOCK_SIZE + heap_base->size > heap_limit)
    {
        broken = 1;
    }

    if (heap_base->next && ((void*)heap_base->next < (void*)heap_base || (void*)heap_base->next >= (void*)heap_limit))
    {
        broken = 1;
    }

    if (heap_base->prev && ((void*)heap_base->prev < (void*)heap_base || (void*)heap_base->prev >= (void*)heap_limit))
    {
        broken = 1;
    }

    if (broken)
    {
        size_t total = (size_t)(heap_limit - (char*)heap_base);

        heap_base->size = total - HEAP_BLOCK_SIZE;
        heap_base->free = 1;
        heap_base->prev = NULL;
        heap_base->next = NULL;
    }
}

// Save IRQ flags and disable interrupts
static inline uint32_t heap_irq_save_cli(void)
{
    uint32_t flags;

    __asm__ volatile("pushf; pop %0; cli" : "=r"(flags) :: "memory");

    return flags;
}

// Restore IRQ flags
static inline void heap_irq_restore(uint32_t flags)
{
    __asm__ volatile("push %0; popf" :: "r"(flags) : "memory", "cc");
}

// Get payload pointer after header
static inline uint8_t* payload_ptr(block_header_t* b)
{
    return (uint8_t*)b + HEAP_BLOCK_SIZE;
}

// Check if pointer is inside heap range
static int in_heap_range(const void* p)
{
    if (!heap_base)
    {
        return 0;
    }

    if (p < (const void*)heap_base)
    {
        return 0;
    }

    if (p >= (const void*)heap_limit)
    {
        return 0;
    }

    return 1;
}

// Quick sanity check of block layout
static int shallow_ok(const block_header_t* b)
{
    if (!in_heap_range(b))
    {
        return 0;
    }

    if ((const char*)b + HEAP_BLOCK_SIZE > heap_limit)
    {
        return 0;
    }

    if ((const char*)b + HEAP_BLOCK_SIZE + b->size > heap_limit)
    {
        return 0;
    }

    return 1;
}

// Split a block if it is too large
static void split_block(block_header_t* b, size_t need)
{
    size_t want = ALIGN(need);

    if (b->size <= want + HEAP_BLOCK_SIZE + ALIGNMENT)
    {
        return;
    }

    block_header_t* nb = (block_header_t*)((uint8_t*)b + HEAP_BLOCK_SIZE + want);
    size_t remain = b->size - want - HEAP_BLOCK_SIZE;

    if (!shallow_ok(b))
    {
        return;
    }

    if ((const char*)nb + HEAP_BLOCK_SIZE + remain > heap_limit)
    {
        return;
    }

    nb->size = remain;
    nb->free = 1;
    nb->prev = b;
    nb->next = b->next;

    if (nb->next)
    {
        nb->next->prev = nb;
    }

    b->size = want;
    b->next = nb;
}

// Merge free blocks if possible
static void coalesce(block_header_t* b)
{
    if (!b)
    {
        return;
    }

    // Forward merge
    if (b->next && b->free && b->next->free)
    {
        block_header_t* n = b->next;

        if (!shallow_ok(b) || !shallow_ok(n))
        {
            return;
        }

        b->size += HEAP_BLOCK_SIZE + n->size;
        b->next = n->next;

        if (b->next)
        {
            b->next->prev = b;
        }
    }

    // Backward merge
    if (b->prev && b->prev->free && b->free)
    {
        block_header_t* p = b->prev;

        if (!shallow_ok(p) || !shallow_ok(b))
        {
            return;
        }

        p->size += HEAP_BLOCK_SIZE + b->size;
        p->next = b->next;

        if (p->next)
        {
            p->next->prev = p;
        }
    }
}

// Initialize the heap with a memory range
void init_heap(void* start, void* end)
{
    if (!start || !end || end <= start)
    {
        printf("[HEAP ERROR] Invalid heap range %p-%p\n", start, end);

        return;
    }

    size_t heap_sz = (size_t)((char*)end - (char*)start);

    if (heap_sz < HEAP_BLOCK_SIZE + ALIGNMENT)
    {
        printf("[HEAP ERROR] Heap too small (%zu bytes)\n", heap_sz);

        return;
    }

    heap_base = (block_header_t*)start;
    heap_limit = (char*)end;

    heap_base->size = heap_sz - HEAP_BLOCK_SIZE;
    heap_base->free = 1;
    heap_base->prev = NULL;
    heap_base->next = NULL;
}

// Allocate memory
void* kmalloc(size_t size)
{
    uint32_t f = heap_irq_save_cli();
    void* out = NULL;

    if (size == 0 || !heap_base)
    {
        heap_irq_restore(f);

        return NULL;
    }

    size_t need = ALIGN(size);

    heap_repair_if_broken();

    block_header_t* cur = heap_base;

    while (cur)
    {
        if (!shallow_ok(cur))
        {
            break;
        }

        if (cur->free && cur->size >= need)
        {
            split_block(cur, need);
            cur->free = 0;
            out = payload_ptr(cur);

            break;
        }

        cur = cur->next;
    }

    heap_irq_restore(f);

    return out;
}

// Free memory
void kfree(void* ptr)
{
    uint32_t f = heap_irq_save_cli();

    if (!ptr || !heap_base)
    {
        heap_irq_restore(f);

        return;
    }

    if (!in_heap_range(ptr))
    {
        heap_irq_restore(f);

        return;
    }

    block_header_t* b = (block_header_t*)((uint8_t*)ptr - HEAP_BLOCK_SIZE);

    if (!shallow_ok(b))
    {
        heap_irq_restore(f);

        return;
    }

    if (b->free)
    {
        heap_irq_restore(f);

        return;
    }

    b->free = 1;
    coalesce(b);

    heap_irq_restore(f);
}

// Print a dump of the heap layout
void heap_dump(void)
{
    if (!heap_base)
    {
        printf("[HEAP DUMP] Heap not initialized\n");

        return;
    }

    printf("\n--- HEAP DUMP (%p-%p) ---\n", heap_base, heap_limit);

    block_header_t* cur = heap_base;
    size_t used = 0;
    size_t freeb = 0;
    int i = 0;

    while (cur)
    {
        if (!shallow_ok(cur))
        {
            printf("[HEAP DUMP] Invalid block at %p\n", cur);

            break;
        }

        printf("Block %d: %p size=%zu %s\n", i++, cur, cur->size, cur->free ? "(free)" : "(used)");

        if (cur->free)
        {
            freeb += cur->size;
        }
        else
        {
            used += cur->size;
        }

        cur = cur->next;
    }

    size_t total = (size_t)(heap_limit - (char*)heap_base);
    size_t over = total - used - freeb;

    printf("\nSUMMARY:\n");
    printf("Total heap space: %zu bytes\n", total);
    printf("Used: %zu bytes\n", used);
    printf("Free: %zu bytes\n", freeb);
    printf("Overhead: %zu bytes\n", over);
    printf("--- END DUMP ---\n\n");
}

