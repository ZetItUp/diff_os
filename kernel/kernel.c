#include "stdio.h"
#include "idt.h"
#include "string.h"
#include "paging.h"
#include "console.h"
#include "idt.h"
#include "irq.h"
#include "pic.h"
#include "io.h"
#include "timer.h"
#include "stdint.h"
#include "heap.h"
#include "drivers/driver.h"

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
void do_tests();

extern char __heap_start;
extern char __heap_end;

extern driver_t keyboard_driver;
int keyboard_pop(void);

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
    
    // Initialize paging and heap
    init_paging(ram_mb);
    init_heap(&__heap_start, &__heap_end);

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


    driver_register(&keyboard_driver);

    //do_tests();

    while(1)
    {
        //print_time();
    }
}

void display_sys_info()
{
    set_color(MAKE_COLOR(FG_YELLOW, BG_BLACK));
    printf("\tS Y S T E M   I N F O\n");     
    set_color(MAKE_COLOR(FG_GRAY, BG_BLACK));   
    printf("[RAM] Available Memory: %u MB\n", system.ram_mb);
}

void do_tests()
{
     
    printf("TEST 1: Testing 4MB mapping...\n");
    map_page(0x400000, 0x400000); // Map 4 MB at virt 4MB
    printf("\t\tMapped 4MB region at 0x400000\n");
    unmap_page(0x400000);
    printf("\t\tUnmapped 4MB region at 0x400000\n");
    
    
    printf("TEST 2: Testing 4KB mapping...\n");
    map_page(0x800000, 8192); // Map 8 KB at virt 8MB
    printf("\t\tMapped 8KB region at 0x800000...\n");
    unmap_page(0x800000);
    printf("\t\tUnmapped 8KB region at 0x800000\n");
    

    printf("TEST 3: Testing physical page alloc/free...\n");
    uint32_t p1 = alloc_phys_page();
    uint32_t p2 = alloc_phys_page();
    printf("\t\tPhys1: 0x%x\n", p1);
    printf("\t\tPhys2: 0x%x\n", p2);
    free_phys_page(p1);
    free_phys_page(p2);
    printf("\t\tFreed both physical pages\n");
    
    printf("TEST 4: Stress test: map 100 small pages...\n");
    for (int i = 0; i < 100; i++) 
    {
        map_page(0xA00000 + (i * 0x1000), 4096);
    }
    printf("\t\tUnmapping 100 small pages...\n");
    for (int i = 0; i < 100; i++) 
    {
        unmap_page(0xA00000 + (i * 0x1000));
    }
    
    printf("TEST 5: Testing mixed mapping...\n");
    // Map 4MB block
    map_page(0xC00000, 0x400000);
    printf("\t\tMapped 4MB at 0xC00000...\n");
    // Map small pages right after
    for (int i = 0; i < 5; i++) 
    {
        map_page(0x1000000 + (i * 0x1000), 4096);
    }
    printf("\t\tUnmapping mixed...\n");
    unmap_page(0xC00000);
    for (int i = 0; i < 5; i++)
    {
        unmap_page(0x1000000 + (i * 0x1000));
    }
    
    printf("TEST 6: Testing alloc/free region...\n");
    alloc_region(0x2000000, 8); // 8MB = 2x 4MB blocks
    printf("\t\tRegion allocated at 0x2000000\n");
    free_region(0x2000000, 8);
    printf("\t\tRegion freed.\n");
    // Reallocate same region
    alloc_region(0x2000000, 8);
    printf("\t\tRegion reallocated successfully.\n");
    free_region(0x2000000, 8);

    printf("TEST 7: Testing fragmentation...");
    map_page(0x3000000, 0x400000);
    map_page(0x7000000, 0x400000);
    unmap_page(0x3000000);
    map_page(0x5000000, 0x400000);
    unmap_page(0x7000000);
    unmap_page(0x5000000);
    printf("done.\n");

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
