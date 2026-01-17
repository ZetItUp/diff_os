#pragma once

#include "stdint.h"
#include "stddef.h"

typedef struct block_header
{
    size_t size;                    /* Usable payload size in bytes (excludes guard) */
    size_t size_inv;                /* ~size for quick corruption detection */
    int    free;                    /* 1 = free, 0 = used */
    struct block_header *next;      /* Next block in list */
    struct block_header *prev;      /* Previous block */
    uint32_t guard;                 /* Per-block guard cookie */
} block_header_t;

#ifndef HEAP_ALIGN
#define HEAP_ALIGN 16  // 16-byte alignment required for fxsave/fxrstor (SSE)
#endif

#define HEAP_ALIGN_UP(n)   (((n) + (HEAP_ALIGN - 1)) & ~(HEAP_ALIGN - 1))
#define HEAP_BLOCK_SIZE    HEAP_ALIGN_UP(sizeof(block_header_t))
#define HEAP_GUARD_SIZE    ((size_t)HEAP_ALIGN) /* keep user payload aligned */
#define HEAP_GUARD_VAL(b)  (0xC0DEF00Du ^ (uint32_t)(uintptr_t)(b))

extern block_header_t *heap_base;
extern char *heap_limit;

void init_heap(void *start, void *end);

void *kmalloc(size_t size);
void kfree(void *ptr);

void heap_dump(void);
int heap_validate(void);
