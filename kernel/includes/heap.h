#pragma once

#include "stdint.h"
#include "stddef.h"

typedef struct block_header
{
    size_t size;                    /* Payload size in bytes */
    int    free;                    /* 1 = free, 0 = used */
    struct block_header *next;      /* Next block in list */
    struct block_header *prev;      /* Previous block */
} block_header_t;

#ifndef HEAP_ALIGN
#define HEAP_ALIGN 8
#endif

#define HEAP_ALIGN_UP(n)   (((n) + (HEAP_ALIGN - 1)) & ~(HEAP_ALIGN - 1))
#define HEAP_BLOCK_SIZE    HEAP_ALIGN_UP(sizeof(block_header_t))

extern block_header_t *heap_base;
extern char *heap_limit;

void init_heap(void *start, void *end);

void *kmalloc(size_t size);
void kfree(void *ptr);

void heap_dump(void);

