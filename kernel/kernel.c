//#include "string.h"
//#include "paging.h"
//#include "console.h"

void kmain(void)
{
    while(1)
        __asm__ __volatile__("mov $0xCAFEBABE, %eax");
}
