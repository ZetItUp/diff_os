#include "idt.h"
#include "string.h"
#include "paging.h"
#include "console.h"
#include "idt.h"
#include "irq.h"
#include "pic.h"
#include "timer.h"
#include "stdint.h"

void display_banner()
{
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    puts("A ");
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    puts("D");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    puts("ifferent ");
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    puts("OS");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
}

void kmain(void)
{
    clear();

        uint32_t esp;
    asm volatile("mov %%esp, %0" : "=r"(esp));
    puts("ESP: 0x"); puthex(esp); puts("\n");

extern struct IDTEntry idt[256];
puts("IDT addr: 0x"); puthex((uint32_t)&idt[0]); puts("\n");


extern void *irq_handlers[];
puts("irq_handlers addr: 0x"); puthex((uint32_t)&irq_handlers[0]); puts("\n");
    // Initialize IDT
    idt_init();
    // Initialize IRQ
    irq_init();
    //dump_idt();
    //int a = 1/0;
    // Remap PIC
    pic_remap(0x20, 0x28);
    // Install timer handler
    timer_install();

    asm volatile("sti");

    display_banner();

    while(1);   
}

