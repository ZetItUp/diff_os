#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <limits.h>

#ifndef ALIGN
#define ALIGN 8u
#endif

#define ALIGN_UP(x) (((x) + (ALIGN - 1)) & ~(ALIGN - 1))

typedef struct block
{
    size_t size;
    struct block *prev;
    struct block *next;
    int free;
} block_t;

static block_t *g_head = NULL;
static block_t *g_tail = NULL;
static int g_initialized = 0;

static void heap_init(void)
{
    // Init lazy list head/tail
    g_head = NULL;
    g_tail = NULL;
    g_initialized = 1;
}

static block_t *find_fit(size_t need)
{
    block_t *b; // Block

    for (b = g_head; b; b = b->next)
    {
        if (b->free && b->size >= need)
        {
            return b;
        }
    }

    return NULL;
}

static void split_block(block_t *b, size_t need)
{
    size_t remain;

    remain = b->size - need;

    if (remain <= sizeof(block_t) + ALIGN)
    {
        return;
    }

    block_t *n; // Next

    n = (block_t *)((uint8_t *)(b + 1) + need);
    n->size = remain - sizeof(block_t);
    n->prev = b;
    n->next = b->next;
    n->free = 1;

    if (b->next)
    {
        b->next->prev = n;
    }

    b->next = n;
    b->size = need;

    if (g_tail == b)
    {
        g_tail = n;
    }
}

static inline block_t *hdr_from_ptr(void *ptr)
{
    return ((block_t *)ptr) - 1;
}

static void try_shrink_tail_from(block_t *b)
{
    // Only shrink if tail chunk is free and at the very end
    if (b && b->free && b->next == NULL && b == g_tail)
    {
        block_t *nt; // New tail

        nt = b->prev;

        if (nt)
        {
            nt->next = NULL;
        }
        else
        {
            g_head = NULL;
        }

        g_tail = nt;

        // Move program break back to header of the freed block
        (void)brk((void *)b);
    }
}

static block_t *extend_heap(size_t need)
{
    size_t total;
    void *base;

    total = sizeof(block_t) + need;

    base = sbrk((intptr_t)total);

    if (base == (void *)-1)
    {
        return NULL;
    }

    if (g_tail && g_tail->free)
    {
        block_t *b; // Block

        g_tail->size += total;
        b = g_tail;

        split_block(b, need);
        b->free = 0;

        return b;
    }

    block_t *b; // Block

    b = (block_t *)base;
    b->size = total - sizeof(block_t);
    b->prev = g_tail;
    b->next = NULL;
    b->free = 1;

    if (g_tail)
    {
        g_tail->next = b;
    }
    else
    {
        g_head = b;
    }

    g_tail = b;

    split_block(b, need);
    b->free = 0;

    return b;
}

static void coalesce(block_t *b)
{
    if (b->next && b->next->free)
    {
        block_t *n; // Next

        n = b->next;
        b->size += sizeof(block_t) + n->size;
        b->next = n->next;

        if (b->next)
        {
            b->next->prev = b;
        }

        if (g_tail == n)
        {
            g_tail = b;
        }
    }

    if (b->prev && b->prev->free)
    {
        block_t *p; // Prev

        p = b->prev;
        p->size += sizeof(block_t) + b->size;
        p->next = b->next;

        if (p->next)
        {
            p->next->prev = p;
        }

        if (g_tail == b)
        {
            g_tail = p;
        }
    }
}

void *malloc(size_t size)
{
    block_t *b; // Block

    if (size == 0)
    {
        return NULL;
    }

    if (!g_initialized)
    {
        heap_init();
    }

    size = ALIGN_UP(size);

    b = find_fit(size);

    if (!b)
    {
        b = extend_heap(size);

        if (!b)
        {
            return NULL;
        }
    }

    if (b->free)
    {
        split_block(b, size);
        b->free = 0;
    }

    return (void *)(b + 1);
}

void free(void *ptr)
{
    block_t *b; // Block

    if (!ptr)
    {
        return;
    }

    b = hdr_from_ptr(ptr);
    b->free = 1;

    coalesce(b);

    try_shrink_tail_from(b);
}

void *calloc(size_t count, size_t size)
{
    size_t total;
    void *p; // Ptr

    if (count && size > SIZE_MAX / count)
    {
        return NULL;
    }

    total = count * size;

    p = malloc(total);

    if (!p)
    {
        return NULL;
    }

    memset(p, 0, total);

    return p;
}

void *realloc(void *ptr, size_t new_size)
{
    block_t *b;      // Block
    size_t old_size;

    if (!ptr)
    {
        return malloc(new_size);
    }

    if (new_size == 0)
    {
        free(ptr);

        return NULL;
    }

    new_size = ALIGN_UP(new_size);

    b = hdr_from_ptr(ptr);
    old_size = b->size;

    if (new_size <= old_size)
    {
        split_block(b, new_size);

        if (b->next && b->next->free && b->next == g_tail)
        {
            try_shrink_tail_from(b->next);
        }

        return ptr;
    }

    if (b->next && b->next->free && old_size + sizeof(block_t) + b->next->size >= new_size)
    {
        block_t *n; // Next

        n = b->next;
        b->size += sizeof(block_t) + n->size;
        b->next = n->next;

        if (b->next)
        {
            b->next->prev = b;
        }

        if (g_tail == n)
        {
            g_tail = b;
        }

        split_block(b, new_size);
        b->free = 0;

        return ptr;
    }

    {
        void *np;       // New ptr
        size_t tocpy;   // Bytes to copy

        np = malloc(new_size);

        if (!np)
        {
            return NULL;
        }

        tocpy = (old_size < new_size) ? old_size : new_size;

        memcpy(np, ptr, tocpy);

        free(ptr);

        return np;
    }
}

void *memset(void *dest, int value, size_t count)
{
    unsigned char *p;  // Ptr
    unsigned char v;   // Val

    p = (unsigned char *)dest;
    v = (unsigned char)value;

    for (size_t i = 0; i < count; i++)
    {
        p[i] = v;
    }

    return dest;
}

void *memcpy(void *dest, const void *src, unsigned int n)
{
    unsigned char *d;        // Dst
    const unsigned char *s;  // Src

    d = (unsigned char *)dest;
    s = (const unsigned char *)src;

    while (n--)
    {
        *d++ = *s++;
    }

    return dest;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d;        // Dst
    const unsigned char *s;  // Src

    d = (unsigned char *)dst;
    s = (const unsigned char *)src;

    if (d == s || n == 0)
    {
        return dst;
    }

    if (d < s)
    {
        for (size_t i = 0; i < n; i++)
        {
            d[i] = s[i];
        }

        return dst;
    }
    else
    {
        for (size_t i = n; i != 0; i--)
        {
            d[i - 1] = s[i - 1];
        }

        return dst;
    }
}

