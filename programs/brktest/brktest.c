#include <unistd.h>
#include <stdio.h>
#include <stdint.h>

int main(void)
{
    void *b0 = sbrk(0);
    printf("brk@start=%p\n", b0);

    // Grow 64 KiB
    void *prev = sbrk(64 * 1024);
    printf("prev=%p new=%p\n", prev, sbrk(0));

    // Touch memory near the top to prove mapping
    volatile uint8_t *p = (uint8_t*)sbrk(0) - 1;
    *p = 0xAB;

    // Shrink back 64 KiB
    brk(prev);

    printf("brk@end=%p\n", sbrk(0));
    return 0;
}

