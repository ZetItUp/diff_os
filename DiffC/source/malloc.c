#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifndef DIFFC_HEAP_SIZE
#define DIFFC_HEAP_SIZE (128 * 1024)  /* 128 KB default */
#endif

#define ALIGN       8u
#define ALIGN_UP(x) (((x) + (ALIGN - 1)) & ~(ALIGN - 1))

typedef struct block 
{
    size_t size;
    struct block *prev;
    struct block *next;
    int free; 
} block_t;

static uint8_t g_heap[DIFFC_HEAP_SIZE] __attribute__((aligned(ALIGN)));
static block_t *g_head = NULL;
static int g_initialized = 0;

static void heap_init(void)
{
    g_head = (block_t *)g_heap;
    g_head->size = DIFFC_HEAP_SIZE - sizeof(block_t);
    g_head->prev = NULL;
    g_head->next = NULL;
    g_head->free = 1;
    g_initialized = 1;
}

static block_t *find_fit(size_t need)
{
    for (block_t *b = g_head; b; b = b->next)
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
    size_t remain = b->size - need;

    if (remain <= sizeof(block_t) + ALIGN)
    {
        return;
    }

    block_t *n = (block_t *)((uint8_t *)(b + 1) + need);
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
}

static inline block_t *hdr_from_ptr(void *ptr)
{
    return ((block_t *)ptr) - 1;
}

static void coalesce(block_t *b)
{
    if (b->next && b->next->free) 
    {
        b->size += sizeof(block_t) + b->next->size;
        b->next = b->next->next;
        
        if (b->next)
        {
            b->next->prev = b;
        }
    }
    
    if (b->prev && b->prev->free) 
    {
        block_t *p = b->prev;
        p->size += sizeof(block_t) + b->size;
        p->next = b->next;
    
        if (p->next)
        {
            p->next->prev = p;
        }

        b = p;
    }
}

void *malloc(size_t size)
{
    if (size == 0)
    {
        return NULL;
    }

    if (!g_initialized)
    {
        heap_init();
    }

    size = ALIGN_UP(size);
    block_t *b = find_fit(size);
    
    if (!b)
    {
        return NULL;
    }

    split_block(b, size);
    b->free = 0;
    
    return (void *)(b + 1);
}

void free(void *ptr)
{
    if (!ptr)
    {
        return;
    }

    block_t *b = hdr_from_ptr(ptr);

    uintptr_t p = (uintptr_t)b;
    uintptr_t h0 = (uintptr_t)g_heap;
    
    if (p < h0 || p >= h0 + DIFFC_HEAP_SIZE)
    {
        return;
    }

    b->free = 1;
    coalesce(b);
}

void *calloc(size_t count, size_t size)
{
    if (count && size > (SIZE_MAX / count))
    {
        return NULL;
    }

    size_t total = count * size;
    void *p = malloc(total);
    
    if (!p)
    {
        return NULL;
    }

    memset(p, 0, total);
    
    return p;
}

void *realloc(void *ptr, size_t new_size)
{
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

    block_t *b = hdr_from_ptr(ptr);
    size_t old_size = b->size;

    if (new_size <= old_size) 
    {
        split_block(b, new_size);
    
        return ptr;
    }

    block_t *n = b->next;
    if (n && n->free && (old_size + sizeof(block_t) + n->size) >= new_size)
    {
        b->size += sizeof(block_t) + n->size;
        b->next = n->next;
        
        if (b->next)
        {
            b->next->prev = b;
        }

        split_block(b, new_size);
        b->free = 0;
        
        return ptr;
    }

    void *np = malloc(new_size);
    
    if (!np)
    {
        return NULL;
    }

    size_t tocpy = old_size < new_size ? old_size : new_size;
    memcpy(np, ptr, tocpy);
    free(ptr);
    
    return np;
}

void *memset(void *dest, int value, size_t count)
{
    unsigned char *ptr = (unsigned char *)dest;
    unsigned char val = (unsigned char)value;

    for(size_t i = 0; i < count; i++)
    {
        ptr[i] = val;
    }

    return dest;
}

void *memcpy(void *dest, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char*)dest;
    const unsigned char *s = (const unsigned char*)src;

    while (n--)
    {
        *d++ = *s++;
    }

    return dest;
}


