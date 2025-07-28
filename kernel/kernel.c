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

__attribute__((naked, section(".text.start"))) 
void _start(void)
{
    asm volatile(
        // Fetch arguments from the old stack
        "mov (%esp), %eax\n\t"      // EAX = bios_mem_map
        "mov 4(%esp), %edx\n\t"     // EDX = mem_entry_count

        "mov $0x9000, %esp\n\t"     // Place a new stack
        "push %edx\n\t"             // mem_entry_count
        "push %eax\n\t"             // bios_mem_map

        "call kmain\n\t"
        "cli\n\t"
        "hlt\n\t"
    );
}

void display_banner();
void display_sys_info();
void print_time();

static sys_info_t system;

void kmain(e820_entry_t *bios_mem_map, uint32_t mem_entry_count)
{
    clear();
    uint32_t total_ram = 0;

    for(uint32_t i = 0; i < mem_entry_count; i++)
    {
        if(bios_mem_map[i].type == 1 && bios_mem_map[i].base_high == 0)
        {
            total_ram += bios_mem_map[i].length_low;
        }
    }

    uint32_t ram_mb = (uint32_t)(total_ram / (1024 * 1024));
    system.ram_mb = ram_mb;
    init_paging(ram_mb);

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
    display_sys_info(); 
    
    while(1)
    {
        //print_time();
    }
}

void display_sys_info()
{
    set_color(MAKE_COLOR(FG_YELLOW, BG_BLACK));
    printf("\n\tS Y S T E M   I N F O\n");     
    set_color(MAKE_COLOR(FG_GRAY, BG_BLACK));   
    printf("[RAM] Available Memory: %u MB\n", system.ram_mb);
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
    printf("OS\n");
    set_color(MAKE_COLOR(FG_GRAY, BG_BLACK));
}
