#include "string.h"
#include "paging.h"
#include "console.h"
#include "idt.h"
#include "stdint.h"

void kmain(void)
{
    idt_init();
    clear();
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    puts("A ");
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    puts("D");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    puts("ifferent ");
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    puts("OS");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));

    while(1);   
}
