#pragma once

#include "stdint.h"
#include "stddef.h"

// Each block has a Meta data header
typedef struct block_header
{
    size_t size;                    // Size of the block
    int free;                       // 1 = Free, 0 = Unavailable
    struct block_header *next;      // Next block in the list
    struct block_header *prev;      // Previous block in the list
} block_header_t;

// Align sizes to 4 bytes
#define ALIGN4(x)   (((((x) - 1) >> 2) << 2) + 4)
#define HEAP_BLOCK_SIZE  ALIGN(sizeof(block_header_t))

extern block_header_t *heap_base;
extern char *heap_limit;
void init_heap(void *start, void *end);
void *kmalloc(size_t size);
void kfree(void *ptr);
void heap_dump();

