#include "stdio.h"
#include "idt.h"
#include "string.h"
#include "paging.h"
#include "console.h"
#include "idt.h"
#include "irq.h"
#include "pic.h"
#include "timer.h"
#include "stdint.h"

__attribute__((naked, section(".text.start"))) void _start(void)
{
    asm volatile("mov $0x9000, %esp");
    asm volatile("call kmain");
    asm volatile("cli; hlt");
}

void display_banner();
void print_time();

void kmain(void)
{
    init_paging();

    clear();

    // Initialize IDT
    idt_init();
    // Remap PIC
    pic_remap(0x20, 0x28);
    // Initialize IRQ
    irq_init();

    // Install timer handler
    timer_install();
    
    asm volatile("sti");
    display_banner();
    putch('\n');
    
    while(1)
    {
        //print_time();
    }
}

void print_time()
{
    if(timer_tick_updated == true)
    {
        timer_tick_updated = false;

        set_x(39);
        set_y(12);
        char buffer[12];
        itoa(timer_ticks, buffer, 10);
        printf("%s", buffer);
    }
}

void display_banner()
{
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    printf("D");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
    printf("ifferent ");
    set_color(MAKE_COLOR(FG_LIGHTGREEN, BG_BLACK));
    printf("OS");
    set_color(MAKE_COLOR(FG_GREEN, BG_BLACK));
}
