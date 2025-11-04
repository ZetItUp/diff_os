#include <stdint.h>
#include <stddef.h>

// Forward declarations for kernel functions
extern int printf(const char *format, ...);
extern void *memset(void *s, int c, size_t n);

// Simple test malloc implementation for kernel testing
typedef struct test_block {
    size_t size;
    struct test_block *prev;
    struct test_block *next;
    int free;
} test_block_t;

static test_block_t *g_test_head = NULL;
static test_block_t *g_test_tail = NULL;
static uint8_t g_test_heap[128 * 1024]; // 128KB test heap
static size_t g_test_heap_used = 0;

static void* test_sbrk(intptr_t incr)
{
    if (incr < 0) return (void*)-1;

    if (g_test_heap_used + incr > sizeof(g_test_heap)) {
        printf("[TEST] sbrk failed: would exceed heap (used=%u, req=%d, max=%u)\n",
               g_test_heap_used, incr, sizeof(g_test_heap));
        return (void*)-1;
    }

    void *old = &g_test_heap[g_test_heap_used];
    g_test_heap_used += incr;

    printf("[TEST] sbrk(%d) = %p (heap_used=%u)\n", incr, old, g_test_heap_used);
    return old;
}

static void* test_malloc(size_t size)
{
    printf("[TEST] malloc(%u) called\n", size);

    if (size == 0) {
        printf("[TEST] malloc(0) -> NULL\n");
        return NULL;
    }

    // Align size
    size = (size + 7) & ~7;

    // Try to find free block
    test_block_t *b = g_test_head;
    while (b) {
        if (b->free && b->size >= size) {
            printf("[TEST] Found free block at %p (size=%u)\n", b, b->size);
            b->free = 0;
            return (void*)(b + 1);
        }
        b = b->next;
    }

    // Need new block
    size_t total = sizeof(test_block_t) + size;
    void *mem = test_sbrk(total);

    if (mem == (void*)-1) {
        printf("[TEST] malloc failed - sbrk returned -1\n");
        return NULL;
    }

    b = (test_block_t*)mem;

    // Zero the header
    memset(b, 0, sizeof(test_block_t));

    b->size = size;
    b->prev = g_test_tail;
    b->next = NULL;
    b->free = 0;

    if (g_test_tail) {
        g_test_tail->next = b;
    } else {
        g_test_head = b;
    }

    g_test_tail = b;

    void *result = (void*)(b + 1);
    printf("[TEST] malloc(%u) -> %p (block at %p)\n", size, result, b);

    return result;
}

static void test_free(void *ptr)
{
    if (!ptr) {
        printf("[TEST] free(NULL)\n");
        return;
    }

    test_block_t *b = ((test_block_t*)ptr) - 1;
    printf("[TEST] free(%p) - block at %p, size=%u\n", ptr, b, b->size);

    b->free = 1;
}

void run_malloc_tests(void)
{
    printf("\n=== KERNEL MALLOC TESTS ===\n");

    // Test 1: Simple allocation
    printf("\n[TEST 1] Simple allocation\n");
    void *p1 = test_malloc(64);
    if (p1) {
        printf("[TEST 1] PASS: allocated 64 bytes at %p\n", p1);
        // Write to it
        memset(p1, 0xAA, 64);
        printf("[TEST 1] PASS: wrote to allocated memory\n");
    } else {
        printf("[TEST 1] FAIL: malloc returned NULL\n");
    }

    // Test 2: Multiple allocations
    printf("\n[TEST 2] Multiple allocations\n");
    void *p2 = test_malloc(128);
    void *p3 = test_malloc(256);
    if (p2 && p3) {
        printf("[TEST 2] PASS: p2=%p, p3=%p\n", p2, p3);
        memset(p2, 0xBB, 128);
        memset(p3, 0xCC, 256);
        printf("[TEST 2] PASS: wrote to all allocations\n");
    } else {
        printf("[TEST 2] FAIL: one allocation failed\n");
    }

    // Test 3: Free and reuse
    printf("\n[TEST 3] Free and reuse\n");
    test_free(p2);
    void *p4 = test_malloc(100);  // Should fit in p2's block
    if (p4) {
        printf("[TEST 3] p4=%p (should be near p2=%p)\n", p4, p2);
        memset(p4, 0xDD, 100);
        printf("[TEST 3] PASS: reused freed block\n");
    } else {
        printf("[TEST 3] FAIL: couldn't allocate after free\n");
    }

    // Test 4: Large allocation
    printf("\n[TEST 4] Large allocation (16KB)\n");
    void *p5 = test_malloc(16 * 1024);
    if (p5) {
        printf("[TEST 4] PASS: allocated 16KB at %p\n", p5);
        memset(p5, 0xEE, 16 * 1024);
        printf("[TEST 4] PASS: wrote to large allocation\n");
    } else {
        printf("[TEST 4] FAIL: large allocation failed\n");
    }

    // Test 5: Dump allocation list
    printf("\n[TEST 5] Allocation list:\n");
    test_block_t *b = g_test_head;
    int count = 0;
    while (b) {
        printf("  Block %d: addr=%p, size=%u, free=%d, prev=%p, next=%p\n",
               count++, b, b->size, b->free, b->prev, b->next);
        b = b->next;
    }

    printf("\n=== MALLOC TESTS COMPLETE ===\n");
    printf("Total heap used: %u / %u bytes\n\n", g_test_heap_used, sizeof(g_test_heap));
}
