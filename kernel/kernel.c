#include "string.h"
#include "paging.h"
#include "console.h"

void kmain(void)
{
     __asm__("movl $0xC0DEBABE, %eax");
//volatile char* lowram = (volatile char*)0x8000;
//for (int i = 0; i < 128; ++i) lowram[i] = 0x55;

//
//    while(1);

    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    putch('M');
    puts("HElLo WoRlD!");

    while(1);
   
}
