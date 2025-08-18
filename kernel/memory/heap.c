// All comments are written in English.
// Allman brace style is used consistently.

#include "heap.h"
#include "stdio.h"
#include "string.h"
#include "stdint.h"

#define ALIGNMENT 8
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define MIN_BLOCK_SIZE (sizeof(block_header_t) + ALIGNMENT)

/* Debug/guard config */
#define GUARD_SIZE   16u
#define GUARD_BYTE   0xC3
#define ALLOC_BYTE   0xAA
#define FREE_BYTE    0xDD

/* Globals provided to the rest of the kernel */
block_header_t *heap_base = NULL; /* First block header */
char *heap_limit = NULL;          /* One past the end of the heap */

/* -------- IRQ guards (always restore on exit) -------- */

static inline uint32_t heap_irq_save_cli(void)
{
    uint32_t flags;

    __asm__ volatile("pushf; pop %0; cli" : "=r"(flags) :: "memory");

    return flags;
}

static inline void heap_irq_restore(uint32_t flags)
{
    __asm__ volatile("push %0; popf" :: "r"(flags) : "memory", "cc");
}

/* ---------- Internal helpers & validation ---------- */

static inline int in_heap_range(const void *p)
{
    return heap_base && p >= (const void *)heap_base && p < (const void *)heap_limit;
}

static inline int is_aligned(const void *p)
{
    return (((uintptr_t)p) & (ALIGNMENT - 1)) == 0;
}

/* guard region is placed at end of the payload; block->size includes GUARD_SIZE for used blocks */
static inline uint8_t* payload_ptr(block_header_t *b)
{
    return (uint8_t *)b + HEAP_BLOCK_SIZE;
}

static inline uint8_t* guard_ptr(block_header_t *b)
{
    /* only meaningful for used blocks; for free blocks we don't care */
    return payload_ptr(b) + b->size - GUARD_SIZE;
}

/* We stash requested size in the first sizeof(size_t) bytes of the payload. */
static inline void set_req_size(block_header_t *b, size_t req)
{
    *(size_t *)payload_ptr(b) = req;
}

static inline size_t get_req_size(const block_header_t *b)
{
    return *(const size_t *)((const uint8_t *)b + HEAP_BLOCK_SIZE);
}

static void set_guard(block_header_t *b)
{
    uint8_t *g;
    size_t i;

    g = guard_ptr(b);

    for (i = 0; i < GUARD_SIZE; i++)
    {
        g[i] = GUARD_BYTE;
    }
}

static int check_guard(const block_header_t *b, const char *tag)
{
    const uint8_t *g;
    size_t i;

    g = (const uint8_t *)payload_ptr((block_header_t *)b) + b->size - GUARD_SIZE;

    for (i = 0; i < GUARD_SIZE; i++)
    {
        if (g[i] != GUARD_BYTE)
        {
            printf("[HEAP GUARD] OVERWRITE in %s at %p (byte %u) req=%zu total=%zu\n",
                   tag, b, (unsigned)i, get_req_size(b), (size_t)b->size);

            return 0;
        }
    }

    return 1;
}

static int validate_block_shallow(const block_header_t *b)
{
    if (!in_heap_range(b) || !is_aligned(b))
    {
        return 0;
    }

    if ((const char *)b + HEAP_BLOCK_SIZE > heap_limit)
    {
        return 0;
    }

    if ((const char *)b + HEAP_BLOCK_SIZE + b->size > heap_limit)
    {
        return 0;
    }

    return 1;
}

static int validate_block_ptr(const block_header_t *b, const char *where)
{
    if (!validate_block_shallow(b))
    {
        printf("[HEAP CORRUPTION] Invalid block header %p at %s\n", b, where);

        return 0;
    }

    if (b->next)
    {
        if (!validate_block_shallow(b->next))
        {
            printf("[HEAP CORRUPTION] Invalid next pointer %p from %p at %s\n",
                   b->next, b, where);

            return 0;
        }

        if (b->next->prev != b)
        {
            printf("[HEAP CORRUPTION] Broken next->prev link at %p (%s)\n", b, where);

            return 0;
        }

        if ((uintptr_t)b->next <= (uintptr_t)b)
        {
            printf("[HEAP CORRUPTION] Non-forward next link %p -> %p at %s\n",
                   b, b->next, where);

            return 0;
        }
    }

    if (b->prev)
    {
        if (!validate_block_shallow(b->prev))
        {
            printf("[HEAP CORRUPTION] Invalid prev pointer %p from %p at %s\n",
                   b->prev, b, where);

            return 0;
        }

        if (b->prev->next != b)
        {
            printf("[HEAP CORRUPTION] Broken prev->next link at %p (%s)\n", b, where);

            return 0;
        }

        if ((uintptr_t)b->prev >= (uintptr_t)b)
        {
            printf("[HEAP CORRUPTION] Non-backward prev link %p <- %p at %s\n",
                   b->prev, b, where);

            return 0;
        }
    }

    return 1;
}

static void split_block(block_header_t *block, size_t wanted_total /* includes GUARD if used */)
{
    size_t aligned_total;
    block_header_t *new_block;
    size_t remaining;

    aligned_total = ALIGN(wanted_total);

    if (block->size <= aligned_total + HEAP_BLOCK_SIZE + ALIGNMENT)
    {
        return;
    }

    new_block = (block_header_t *)((uint8_t *)block + HEAP_BLOCK_SIZE + aligned_total);
    remaining = block->size - aligned_total - HEAP_BLOCK_SIZE;

    if (!validate_block_shallow(block))
    {
        printf("[KMALLOC] ERROR: split on invalid block %p\n", block);

        return;
    }

    if ((const char *)new_block + HEAP_BLOCK_SIZE + remaining > heap_limit)
    {
        printf("[KMALLOC] ERROR: Split would exceed heap (block=%p)\n", block);

        return;
    }

    new_block->size = remaining;
    new_block->free = 1;
    new_block->prev = block;
    new_block->next = block->next;

    if (new_block->next)
    {
        new_block->next->prev = new_block;
    }

    block->size = aligned_total;
    block->next = new_block;
}

static void coalesce_with_next(block_header_t *b)
{
    block_header_t *n;

    if (!b || !b->next || !b->free || !b->next->free)
    {
        return;
    }

    if (!validate_block_ptr(b, "coalesce.this") ||
        !validate_block_ptr(b->next, "coalesce.next"))
    {
        return;
    }

    n = b->next;

    if ((const char *)n + HEAP_BLOCK_SIZE + n->size > heap_limit)
    {
        printf("[HEAP] WARNING: Coalesce would exceed heap bounds\n");

        return;
    }

    b->size += HEAP_BLOCK_SIZE + n->size;
    b->next = n->next;

    if (b->next)
    {
        b->next->prev = b;
    }
}

static int heap_validate(void)
{
    block_header_t *cur;
    size_t accounted;
    int safety;

    if (!heap_base)
    {
        return 0;
    }

    cur = heap_base;
    accounted = 0;
    safety = 0;

    while (cur)
    {
        if (!validate_block_ptr(cur, "heap_validate"))
        {
            return 0;
        }

        /* For used blocks, verify guard */
        if (!cur->free)
        {
            (void)check_guard(cur, "heap_validate");
        }

        accounted += HEAP_BLOCK_SIZE + cur->size;

        if (cur->next && (uintptr_t)cur->next <= (uintptr_t)cur)
        {
            printf("Heap corruption: Non-forward link at %p\n", cur);

            return 0;
        }

        cur = cur->next;

        if (++safety > (1 << 20))
        {
            printf("Heap corruption: Infinite loop suspected\n");

            return 0;
        }
    }

    {
        size_t total;

        total = (size_t)(heap_limit - (char *)heap_base);

        if (accounted > total)
        {
            printf("Heap corruption: Accounted bytes %zu > total %zu\n", accounted, total);

            return 0;
        }
    }

    return 1;
}

/* ---------- Public API ---------- */

void init_heap(void *start, void *end)
{
    size_t heap_size;

    if (!start || !end || end <= start)
    {
        printf("ERROR: Invalid heap range %p-%p\n", start, end);

        return;
    }

    heap_size = (size_t)((char *)end - (char *)start);

    if (heap_size < MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE)
    {
        printf("ERROR: Heap too small (%zu bytes), need at least %zu\n",
               heap_size, MIN_BLOCK_SIZE + HEAP_BLOCK_SIZE);

        return;
    }

    heap_base = (block_header_t *)start;
    heap_limit = (char *)end;

    heap_base->size = heap_size - HEAP_BLOCK_SIZE;
    heap_base->free = 1;
    heap_base->next = NULL;
    heap_base->prev = NULL;

    /* mark whole area as FREE_BYTE for easier spotting */
    memset(payload_ptr(heap_base), FREE_BYTE, heap_base->size);
}

void* kmalloc(size_t size)
{
    uint32_t irqf;
    void *result;
    size_t req;             /* requested size by caller */
    size_t aligned_req;     /* aligned payload given to caller (excluding guard & req-size slot) */
    size_t total_needed;    /* aligned_req + GUARD_SIZE, plus space for storing req at start */
    block_header_t *current;
    block_header_t *best_fit;
    size_t best_fit_size;
    int safety_counter;
    uint8_t *ret;

    irqf = heap_irq_save_cli();
    result = NULL;

    if (size == 0)
    {
        printf("[KMALLOC] WARNING: Zero-size allocation\n");
        goto out;
    }

    if (!heap_base)
    {
        printf("[KMALLOC] ERROR: Heap not initialized\n");
        goto out;
    }

    /* We reserve sizeof(size_t) at the beginning of payload to store req-size */
    req = size;
    aligned_req = ALIGN(req + sizeof(size_t));
    total_needed = aligned_req + GUARD_SIZE;

    current = heap_base;
    best_fit = NULL;
    best_fit_size = 0;
    safety_counter = 0;

    while (current)
    {
        if (!validate_block_ptr(current, "kmalloc.iter"))
        {
            heap_dump();
            goto out;
        }

        if (current->free)
        {
            if (current->size >= total_needed)
            {
                if (current->size == total_needed)
                {
                    best_fit = current;
                    break;
                }

                if (!best_fit || current->size < best_fit_size)
                {
                    best_fit = current;
                    best_fit_size = current->size;
                }
            }
        }

        if (current->next && !validate_block_shallow(current->next))
        {
            printf("[KMALLOC] ERROR: Corrupt next pointer from %p\n", current);
            heap_dump();
            goto out;
        }

        current = current->next;

        if (++safety_counter > (1 << 20))
        {
            printf("[KMALLOC] ERROR: Infinite loop (corrupt list)\n");
            heap_dump();
            goto out;
        }
    }

    if (!best_fit)
    {
        printf("[KMALLOC] ERROR: Out of memory for %zu bytes (tot=%zu)\n",
               req, total_needed);
        goto out;
    }

    if (best_fit->size >= total_needed + MIN_BLOCK_SIZE)
    {
        split_block(best_fit, total_needed);

        if (best_fit->next && !validate_block_ptr(best_fit->next, "kmalloc.split.new"))
        {
            printf("[KMALLOC] ERROR: Split produced invalid pointer\n");
            heap_dump();
            goto out;
        }
    }

    best_fit->free = 0;

    /* set patterns and guards */
    memset(payload_ptr(best_fit), ALLOC_BYTE, best_fit->size);
    set_req_size(best_fit, req);
    set_guard(best_fit);

    /* return pointer after the req-size header */
    ret = payload_ptr(best_fit) + sizeof(size_t);
    result = (void *)ret;

out:
    heap_irq_restore(irqf);
    return result;
}

void kfree(void *ptr)
{
    uint32_t irqf;
    block_header_t *block;
    uint8_t *user_ptr;

    irqf = heap_irq_save_cli();

    if (!ptr)
    {
        printf("[KFREE] WARNING: Null pointer free\n");
        goto out;
    }

    if (!heap_base)
    {
        printf("[KFREE] ERROR: Heap not initialized\n");
        goto out;
    }

    /* user_ptr is what caller gave; block payload starts sizeof(size_t) before that */
    user_ptr = (uint8_t *)ptr;

    if (user_ptr < (uint8_t *)heap_base + HEAP_BLOCK_SIZE + sizeof(size_t) ||
        user_ptr >= (uint8_t *)heap_limit)
    {
        printf("[KFREE] ERROR: Pointer %p outside heap range\n", ptr);
        goto out;
    }

    block = (block_header_t *)(user_ptr - sizeof(size_t) - HEAP_BLOCK_SIZE);

    if (!validate_block_ptr(block, "kfree.block"))
    {
        heap_dump();
        goto out;
    }

    if (block->free)
    {
        printf("[KFREE] ERROR: Double free at %p\n", ptr);
        goto out;
    }

    /* verify guard on free */
    (void)check_guard(block, "kfree");

    block->free = 1;

    /* stamp freed area */
    memset(payload_ptr(block), FREE_BYTE, block->size);

    /* Coalesce with neighbors when possible */
    coalesce_with_next(block);

    if (block->prev && block->prev->free)
    {
        coalesce_with_next(block->prev);
    }

out:
    heap_irq_restore(irqf);
}

void heap_dump(void)
{
    block_header_t *current;
    size_t total_used;
    size_t total_free;
    int block_count;
    int safety;

    if (!heap_base)
    {
        printf("[HEAP DUMP] Heap not initialized\n");

        return;
    }

    if (!heap_validate())
    {
        printf("[HEAP DUMP] WARNING: Heap corruption detected!\n");
    }

    printf("\n--- HEAP DUMP (%p-%p) ---\n", heap_base, heap_limit);

    current = heap_base;
    total_used = 0;
    total_free = 0;
    block_count = 0;
    safety = 0;

    while (current)
    {
        if (!validate_block_ptr(current, "heap_dump.iter"))
        {
            printf("[HEAP DUMP] Abort: invalid block at %p\n", current);

            break;
        }

        printf("Block %d: %p size=%zu %s",
               block_count++, current, current->size,
               current->free ? "(free)" : "(used)");

        if (current->prev)
        {
            printf(" prev=%p", current->prev);
        }

        if (current->next)
        {
            printf(" next=%p", current->next);
        }

        if (!current->free)
        {
            size_t req;

            req = get_req_size(current);
            printf(" req=%zu", req);
            (void)check_guard(current, "heap_dump");
        }

        printf("\n");

        if (current->free)
        {
            total_free += current->size;
        }
        else
        {
            total_used += current->size;
        }

        if (current->next && !validate_block_shallow(current->next))
        {
            printf("[HEAP DUMP] Stopping: corrupt next pointer from %p\n", current);

            break;
        }

        current = current->next;

        if (++safety > (1 << 20))
        {
            printf("[HEAP DUMP] Stopping due to suspected loop\n");

            break;
        }
    }

    {
        size_t total_space;
        size_t overhead;
        int used_pct;
        int free_pct;
        int over_pct;

        total_space = (size_t)(heap_limit - (char *)heap_base);
        overhead = total_space - total_used - total_free;

        used_pct = (total_space != 0) ? (int)((total_used * 100) / total_space) : 0;
        free_pct = (total_space != 0) ? (int)((total_free * 100) / total_space) : 0;
        over_pct = (total_space != 0) ? (int)((overhead * 100) / total_space) : 0;

        printf("\nSUMMARY:\n");
        printf("Total heap space: %zu bytes\n", total_space);
        printf("Used: %zu bytes (%d)\n", total_used, used_pct);
        printf("Free: %zu bytes (%d)\n", total_free, free_pct);
        printf("Overhead: %zu bytes (%d)\n", overhead, over_pct);
        printf("--- END DUMP ---\n\n");
    }
}

