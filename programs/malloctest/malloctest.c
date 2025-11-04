#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("\n=== USERSPACE MALLOC/SBRK TEST ===\n\n");

    // Test 1: Basic sbrk
    printf("[TEST 1] Testing sbrk(0) - get current break\n");
    void *initial_brk = sbrk(0);
    printf("  Initial break: %p\n", initial_brk);
    if (initial_brk == (void*)-1) {
        printf("  FAIL: sbrk(0) returned -1\n");
        return 1;
    }
    printf("  PASS\n\n");

    // Test 2: Extend heap with sbrk
    printf("[TEST 2] Testing sbrk(1024) - extend heap\n");
    void *mem1 = sbrk(1024);
    printf("  sbrk(1024) returned: %p\n", mem1);
    if (mem1 == (void*)-1) {
        printf("  FAIL: sbrk(1024) returned -1\n");
        return 1;
    }

    void *new_brk = sbrk(0);
    printf("  New break: %p\n", new_brk);
    printf("  Expected: %p (old + 1024)\n", (void*)((char*)mem1 + 1024));

    // Write to allocated memory
    printf("  Writing to allocated memory...\n");
    memset(mem1, 0xAA, 1024);
    printf("  PASS: wrote 1024 bytes\n\n");

    // Test 3: Basic malloc
    printf("[TEST 3] Testing malloc(64)\n");
    void *p1 = malloc(64);
    printf("  malloc(64) = %p\n", p1);
    if (p1 == NULL) {
        printf("  FAIL: malloc returned NULL\n");
        return 1;
    }
    memset(p1, 0xBB, 64);
    printf("  PASS: allocated and wrote 64 bytes\n\n");

    // Test 4: Multiple mallocs
    printf("[TEST 4] Testing multiple malloc calls\n");
    void *p2 = malloc(128);
    void *p3 = malloc(256);
    void *p4 = malloc(512);
    printf("  p2 (128 bytes) = %p\n", p2);
    printf("  p3 (256 bytes) = %p\n", p3);
    printf("  p4 (512 bytes) = %p\n", p4);

    if (!p2 || !p3 || !p4) {
        printf("  FAIL: one or more mallocs returned NULL\n");
        return 1;
    }

    memset(p2, 0xCC, 128);
    memset(p3, 0xDD, 256);
    memset(p4, 0xEE, 512);
    printf("  PASS: allocated and wrote to all blocks\n\n");

    // Test 5: Free and malloc
    printf("[TEST 5] Testing free() and reallocation\n");
    printf("  Freeing p3 (%p)...\n", p3);
    free(p3);

    void *p5 = malloc(200);
    printf("  malloc(200) after free = %p\n", p5);
    printf("  Should reuse freed block if allocator is smart\n");
    if (p5 == NULL) {
        printf("  FAIL: malloc returned NULL\n");
        return 1;
    }
    memset(p5, 0xFF, 200);
    printf("  PASS\n\n");

    // Test 6: Large allocation
    printf("[TEST 6] Testing large allocation (8KB)\n");
    void *p6 = malloc(8192);
    printf("  malloc(8192) = %p\n", p6);
    if (p6 == NULL) {
        printf("  FAIL: malloc returned NULL\n");
        return 1;
    }

    printf("  Writing to large allocation...\n");
    for (int i = 0; i < 8192; i++) {
        ((char*)p6)[i] = (char)(i & 0xFF);
    }

    // Verify
    int errors = 0;
    for (int i = 0; i < 8192; i++) {
        if (((char*)p6)[i] != (char)(i & 0xFF)) {
            errors++;
        }
    }
    printf("  Verification: %d errors\n", errors);
    if (errors > 0) {
        printf("  FAIL: memory corruption detected\n");
        return 1;
    }
    printf("  PASS\n\n");

    // Test 7: calloc
    printf("[TEST 7] Testing calloc(10, 100)\n");
    void *p7 = calloc(10, 100);
    printf("  calloc(10, 100) = %p\n", p7);
    if (p7 == NULL) {
        printf("  FAIL: calloc returned NULL\n");
        return 1;
    }

    // Verify it's zeroed
    int non_zero = 0;
    for (int i = 0; i < 1000; i++) {
        if (((char*)p7)[i] != 0) {
            non_zero++;
        }
    }
    printf("  Non-zero bytes: %d (should be 0)\n", non_zero);
    if (non_zero > 0) {
        printf("  FAIL: calloc didn't zero memory\n");
        return 1;
    }
    printf("  PASS\n\n");

    printf("=== ALL TESTS PASSED ===\n");
    printf("Malloc/sbrk working correctly!\n\n");

    return 0;
}
