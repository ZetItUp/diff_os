#include "heap.h"
#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include "paging.h"

/* ---------------- Internal helpers ---------------- */

static inline void poison_bytes(void *p, size_t n, uint8_t val)
{
    if (p && n) memset(p, val, n);
}

block_header_t* heap_base = NULL;
char* heap_limit = NULL;

/* Save IRQ flags and disable interrupts */
static inline uint32_t heap_irq_save_cli(void)
{
    uint32_t flags;
    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

/* Restore IRQ flags */
static inline void heap_irq_restore(uint32_t flags)
{
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory", "cc");
}

/* Payload pointer after header */
static inline uint8_t* payload_ptr(block_header_t* b)
{
    return (uint8_t*)b + HEAP_BLOCK_SIZE;
}

/* User-visible pointer (after guard) */
static inline uint8_t* user_ptr(block_header_t* b)
{
    return payload_ptr(b) + HEAP_GUARD_SIZE;
}

/* Check if pointer is inside heap range */
static int in_heap_range(const void* p)
{
    if (!heap_base || !heap_limit) return 0;
    return (p >= (const void*)heap_base) && (p < (const void*)heap_limit);
}

/* Return pointer only if it is inside the heap window and header fits. */
static inline block_header_t* valid_link(block_header_t* p)
{
    if (!p) return NULL;
    if (!in_heap_range(p)) return NULL;
    const char* end_hdr = (const char*)p + HEAP_BLOCK_SIZE;
    if (end_hdr > heap_limit) return NULL;
    return p;
}

static inline size_t block_span_bytes(const block_header_t* b)
{
    return HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + b->size;
}

static inline int header_ok(const block_header_t* b)
{
    if (!b) return 0;
    if (b->size_inv != ~b->size) return 0;
    return 1;
}

static inline void stamp_guard(block_header_t* b)
{
    b->guard = HEAP_GUARD_VAL(b);
    /* Fill entire guard region with the cookie for quick detection */
    uint8_t *g = payload_ptr(b);
    for (size_t i = 0; i < HEAP_GUARD_SIZE; i += sizeof(uint32_t))
    {
        *(uint32_t*)(g + i) = b->guard;
    }
}

static inline int guard_ok(const block_header_t* b)
{
    const uint8_t *g = payload_ptr((block_header_t*)b);
    uint32_t want = HEAP_GUARD_VAL(b);
    for (size_t i = 0; i < HEAP_GUARD_SIZE; i += sizeof(uint32_t))
    {
        if (*(const uint32_t*)(g + i) != want) return 0;
    }
    return 1;
}

static inline void stamp_header(block_header_t* b, size_t size, int free_flag)
{
    b->size = size;
    b->size_inv = ~size;
    b->free = free_flag;
    stamp_guard(b);
}

/* Quick sanity check of block layout */
static int shallow_ok(const block_header_t* b)
{
    if (!in_heap_range(b)) return 0;
    if (!header_ok(b))
    {
        /* Attempt gentle repair for free blocks with bad size_inv */
        block_header_t *w = (block_header_t*)b;
        if (w->free)
        {
            w->size_inv = ~w->size;
        }
        else
        {
            return 0;
        }
    }
    const char* end_hdr = (const char*)b + HEAP_BLOCK_SIZE;
    if (end_hdr > heap_limit) return 0;
    if (end_hdr + HEAP_GUARD_SIZE + b->size > heap_limit) return 0;
    if (!guard_ok(b))
    {
        block_header_t *w = (block_header_t*)b;
        if (w->free)
        {
            stamp_guard(w);
        }
        else
        {
            return 0;
        }
    }
    /* Links must either be NULL or fall inside the heap window */
    if (b->next && !in_heap_range(b->next)) return 0;
    if (b->prev && !in_heap_range(b->prev)) return 0;
    return 1;
}

/* If first block looks broken, rebuild a single free block */
static void heap_repair_if_broken(void)
{
    if (!heap_base || !heap_limit) return;
    if ((char*)heap_base + HEAP_BLOCK_SIZE > heap_limit) return;

    int broken = 0;

    if (heap_base->size == 0) broken = 1;
    if ((char*)heap_base + HEAP_BLOCK_SIZE + heap_base->size > heap_limit) broken = 1;

    if (heap_base->next &&
        ((void*)heap_base->next < (void*)heap_base || (void*)heap_base->next >= (void*)heap_limit))
        broken = 1;

    if (heap_base->prev &&
        ((void*)heap_base->prev < (void*)heap_base || (void*)heap_base->prev >= (void*)heap_limit))
        broken = 1;

    if (broken)
    {
        size_t total = (size_t)(heap_limit - (char*)heap_base);
        size_t usable = (total > (HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE)) ? (total - HEAP_BLOCK_SIZE - HEAP_GUARD_SIZE) : 0;
        stamp_header(heap_base, usable, 1);
        heap_base->prev = NULL;
        heap_base->next = NULL;
        stamp_guard(heap_base);
    }
}

/* Split a block if it is too large */
static void split_block(block_header_t* b, size_t need)
{
    size_t want = HEAP_ALIGN_UP(need);
    size_t min_rem = HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + HEAP_ALIGN;

    /* Not enough room for a split + new header + minimal payload */
    if (b->size <= want + min_rem)
    {
        /* No split - leave next pointer as is */
        return;
    }

    /* Defensive overflow/consistency checks */
    if (want > b->size)
    {
        printf("[HEAP] split overflow check: want=%zu > b->size=%zu\n", want, b->size);
        return;
    }
    if (!shallow_ok(b))
    {
        printf("[HEAP] split shallow_ok failed for b=%p\n", b);
        return;
    }

    block_header_t* nb = (block_header_t*)((uint8_t*)b + HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + want);
    /* Hard guard: never create headers in user space */
    if ((uintptr_t)nb >= (uintptr_t)USER_MIN)
    {
        printf("[HEAP] split nb=%p >= USER_MIN=%p\n", nb, (void*)USER_MIN);
        return;
    }
    /* Account for header+guard overhead taken by the new block */
    size_t remain = b->size - want - (HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE);

    /* New header must lie entirely inside the heap window */
    if (!in_heap_range(nb))
    {
        printf("[HEAP] split nb=%p not in heap range\n", nb);
        return;
    }
    if ((const char*)nb + HEAP_BLOCK_SIZE > heap_limit)
    {
        printf("[HEAP] split nb+hdr=%p > heap_limit=%p\n", (const char*)nb + HEAP_BLOCK_SIZE, heap_limit);
        return;
    }

    /* Entire new block (header + guard + payload) must fit */
    if ((const char*)nb + HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + remain > heap_limit)
    {
        printf("[HEAP] split nb+hdr+remain > heap_limit\n");
        return;
    }

    stamp_header(nb, remain, 1);
    nb->prev = b;
    nb->next = valid_link(b->next);
    if (b->next && !nb->next)
    {
        /* Drop bogus next pointer to avoid later crashes */
        b->next = NULL;
    }
    if (nb->next) nb->next->prev = nb;

    stamp_header(b, want, b->free);
    b->next = nb;
}

/* Merge free blocks if possible */
static void coalesce(block_header_t* b)
{
    if (!b) return;

    /* Forward merge */
    block_header_t* n = valid_link(b->next);
    if (n && b->free && n->free)
    {
        if (!shallow_ok(b) || !shallow_ok(n)) return;

        b->size += HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + n->size;
        b->next = n->next;
        if (b->next && !valid_link(b->next)) b->next = NULL;
        if (b->next) b->next->prev = b;
        stamp_guard(b);
    }
    else if (b->next && !n)
    {
        /* Broken forward link, drop it */
        b->next = NULL;
    }

    /* Backward merge */
    block_header_t* p = valid_link(b->prev);
    if (p && p->free && b->free)
    {
        if (!shallow_ok(p) || !shallow_ok(b)) return;

        p->size += HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE + b->size;
        p->next = b->next;
        if (p->next && !valid_link(p->next)) p->next = NULL;
        if (p->next) p->next->prev = p;
        stamp_guard(p);
    }
    else if (b->prev && !p)
    {
        /* Broken backward link, drop it */
        b->prev = NULL;
    }
}

/* ---------------- Public API ---------------- */

/* Initialize the heap with a memory range [start, end). No clamping to USER_MIN here. */
void init_heap(void* start, void* end)
{
    if (!start || !end || end <= start)
    {
        printf("[HEAP ERROR] Invalid heap range %p-%p\n", start, end);
        return;
    }

    uintptr_t s = (uintptr_t)start;
    uintptr_t e = (uintptr_t)end;

    /* Align bounds: start up, end down */
    s = HEAP_ALIGN_UP(s);
    e &= ~((uintptr_t)HEAP_ALIGN - 1);

    /* Clamp kernel heap to stay strictly below the user window */
    if (e > (uintptr_t)USER_MIN)
    {
        printf("[HEAP] clamping end from %p to %p to avoid USER_MIN\n", (void*)e, (void*)USER_MIN);
        e = (uintptr_t)USER_MIN;
    }
    if (s >= e)
    {
        printf("[HEAP ERROR] Heap range after clamp invalid %p-%p\n", (void*)s, (void*)e);
        return;
    }

    if (e <= s + HEAP_BLOCK_SIZE)
    {
        printf("[HEAP ERROR] Heap too small after alignment (%zu bytes)\n", (size_t)(e - s));
        return;
    }

    heap_base  = (block_header_t*)s;
    heap_limit = (char*)e;

    size_t heap_sz = (size_t)(heap_limit - (char*)heap_base);
    size_t usable = (heap_sz > (HEAP_BLOCK_SIZE + HEAP_GUARD_SIZE)) ? (heap_sz - HEAP_BLOCK_SIZE - HEAP_GUARD_SIZE) : 0;
    stamp_header(heap_base, usable, 1);
    heap_base->prev = NULL;
    heap_base->next = NULL;
    stamp_guard(heap_base);

#ifdef DIFF_DEBUG
    printf("[HEAP] init %p-%p (%zu bytes usable)\n",
           heap_base, heap_limit, (size_t)heap_base->size);
#endif
}

void* kmalloc(size_t size)
{
    uint32_t f = heap_irq_save_cli();
    void* out = NULL;

    if (size == 0 || !heap_base)
    {
        heap_irq_restore(f);
        return NULL;
    }

    size_t need = HEAP_ALIGN_UP(size);
    heap_repair_if_broken();

    block_header_t* cur = heap_base;
    int repaired_once = 0;
    while (cur)
    {
        if (!shallow_ok(cur))
        {
            printf("[HEAP ERROR] shallow_ok failed in kmalloc cur=%p\n", cur);
            printf("[HEAP ERROR] cur->size=%zu cur->free=%d cur->next=%p cur->prev=%p\n",
                   cur->size, cur->free, cur->next, cur->prev);
            printf("[HEAP ERROR] heap_base=%p heap_limit=%p\n", heap_base, heap_limit);
            printf("[HEAP ERROR] in_heap_range(cur)=%d header_ok=%d guard_ok=%d\n",
                   in_heap_range(cur), header_ok(cur), guard_ok(cur));
            if (in_heap_range(cur)) {
                const char* end_hdr = (const char*)cur + HEAP_BLOCK_SIZE;
                printf("[HEAP ERROR] end_hdr=%p (> heap_limit? %d)\n",
                       end_hdr, (end_hdr > heap_limit));
                printf("[HEAP ERROR] end_hdr + guard+size = %p (> heap_limit? %d)\n",
                       end_hdr + HEAP_GUARD_SIZE + cur->size, (end_hdr + HEAP_GUARD_SIZE + cur->size > heap_limit));
            }
            /* Try a single repair pass to recover from corrupted links (e.g. stack smash). */
            if (!repaired_once)
            {
                heap_repair_if_broken();
                repaired_once = 1;
                cur = heap_base;
                continue;
            }

            heap_dump();
            heap_irq_restore(f);
            return NULL;
        }

        if (cur->free && cur->size >= need)
        {
            split_block(cur, need);
            cur->free = 0;
            stamp_guard(cur);
            poison_bytes(user_ptr(cur), cur->size, 0xA5);
            out = user_ptr(cur);
            break;
        }

        cur = valid_link(cur->next);
    }

    heap_irq_restore(f);
    return out;
}

void kfree(void* ptr)
{
    uint32_t f = heap_irq_save_cli();

    if (!ptr || !heap_base)
    {
        heap_irq_restore(f);
        return;
    }

    if (!in_heap_range((uint8_t*)ptr - HEAP_GUARD_SIZE))
    {
        heap_irq_restore(f);
        return;
    }

    block_header_t* b = (block_header_t*)((uint8_t*)ptr - HEAP_BLOCK_SIZE - HEAP_GUARD_SIZE);

    if (!shallow_ok(b))
    {
        printf("[HEAP ERROR] shallow_ok failed in kfree b=%p ptr=%p\n", b, ptr);
        heap_dump();
        heap_irq_restore(f);
        return;
    }
    if (!guard_ok(b))
    {
        printf("[HEAP ERROR] guard corrupted in kfree b=%p\n", b);
        heap_dump();
        heap_irq_restore(f);
        return;
    }

    if (b->free)
    {
        heap_irq_restore(f);
        return;
    }

    poison_bytes(user_ptr(b), b->size, 0xDE);
    b->free = 1;
    stamp_guard(b);
    coalesce(b);

    heap_irq_restore(f);
}

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

        if (cur->free)  freeb += cur->size;
        else            used  += cur->size;

        cur = cur->next;
    }

    size_t total = (size_t)(heap_limit - (char*)heap_base);
    size_t over  = total - used - freeb;

    printf("\nSUMMARY:\n");
    printf("Total heap space: %zu bytes\n", total);
    printf("Used: %zu bytes\n", used);
    printf("Free: %zu bytes\n", freeb);
    printf("Overhead: %zu bytes\n", over);
    printf("--- END DUMP ---\n\n");
}

int heap_validate(void)
{
    if (!heap_base) return -1;
    block_header_t* cur = heap_base;
    while (cur)
    {
        if (!shallow_ok(cur))
        {
            printf("[HEAP VALIDATE] Invalid block at %p\n", cur);
            return -1;
        }
        cur = cur->next;
    }
    return 0;
}
