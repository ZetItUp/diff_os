#include "stdio.h"
#include "idt.h"
#include "string.h"
#include "paging.h"
#include "console.h"
#include "serial.h"
#include "irq.h"
#include "pic.h"
#include "io.h"
#include "timer.h"
#include "stdint.h"
#include "heap.h"
#include "diff.h"
#include "system.h"
#include "graphics/vbe_text.h"
#include "drivers/module_loader.h"
#include "drivers/config.h"
#include "drivers/driver.h"
#include "drivers/ata.h"
#include "dex/dex.h"
#include "system/threads.h"
#include "system/scheduler.h"


__attribute__((naked, section(".text.start")))
void _start(void)
{
    asm volatile(
        "mov (%esp), %eax\n\t"
        "mov 4(%esp), %edx\n\t"
        "mov $0x20000, %esp\n\t"
        "push %edx\n\t"
        "push %eax\n\t"
        "call kmain\n\t"
        "cli\n\t"
        "hlt\n\t"
    );
}

// Types

extern char __heap_start;
extern char __heap_end;

// State

static sys_info_t system;
static char background = BG_BLACK;
static char foreground = FG_GRAY;

// Prototypes

static void init_thread(void* argument);
void display_banner(void);
void display_sys_info(void);
void test_ata_read(void);
void do_tests(void);

// Entry


// Kernel

void kmain(e820_entry_t* bios_mem_map, uint32_t mem_entry_count)
{
    serial_init();

    set_color(MAKE_COLOR(foreground, background));
    clear();

    uint32_t total_ram = 0;
    for (uint32_t i = 0; i < mem_entry_count; i++)
    {
        if (bios_mem_map[i].type == 1 && bios_mem_map[i].base_high == 0)
        {
            total_ram += bios_mem_map[i].length_low;
        }
    }
    uint32_t ram_mb = (uint32_t)(total_ram / (1024 * 1024));
    system.ram_mb = ram_mb;
    
    init_paging(ram_mb);
    init_heap(&__heap_start, &__heap_end);

    idt_init();
    pic_remap(0x20, 0x28);
    irq_init();
    timer_install();
    scheduler_init();
    thread_create(init_thread, NULL, 4096);

    asm volatile("sti");
    scheduler_start();

    for (;;)
    {
    }
}

// Init

static void init_thread(void* argument)
{
    (void)argument;
    asm volatile("sti"); 
    vga_capture_rom_font_early();
    uint8_t h = vga_cell_height();
    vga_cursor_enable(0, h - 1);
    
    init_filesystem();
    display_banner();
    display_sys_info();

    char* system_config_file = "system/sys.cfg";
    load_drivers(file_table, system_config_file);
    
    for (;;)
    {
        char* shell_path = find_shell_path(file_table, system_config_file);
        if (shell_path)
        {
            int result = dex_run(file_table, shell_path, 0, 0);
            kfree(shell_path);
            printf("[init] shell exited with code %d, restarting in 1000 ms...\n", result);
        }
        else
        {
            printf("[ERROR] No shell was set! Retrying in 1000 ms...\n");
        }
        
        sleep_ms(1000);
    }
}

// UI

void display_banner(void)
{
    int x;
    int y;
    get_cursor(&x, &y);
    set_pos(0, 0);
    set_color(MAKE_COLOR(FG_LIGHTCYAN, BG_BLACK));
    printf(" D");
    set_color(MAKE_COLOR(FG_CYAN, BG_BLACK));
    printf("ifferent ");
    set_color(MAKE_COLOR(FG_LIGHTCYAN, BG_BLACK));
    printf("OS");
    set_color(MAKE_COLOR(FG_GRAY, BG_BLACK));
    set_pos(x, y);
}

void display_sys_info(void)
{
    printf("\n[RAM] Available Memory: %u MB\n", system.ram_mb);
}

// Tests

void do_tests(void)
{
    printf("TEST 1: Testing 4MB mapping...\n");
    map_page(0x400000, 0x400000);
    printf("\t\tMapped 4MB region at 0x400000\n");
    unmap_page(0x400000);
    printf("\t\tUnmapped 4MB region at 0x400000\n");

    printf("TEST 2: Testing 4KB mapping...\n");
    map_page(0x800000, 8192);
    printf("\t\tMapped 8KB region at 0x800000...\n");
    unmap_page(0x800000);
    printf("\t\tUnmapped 8KB region at 0x800000\n");

    printf("TEST 3: Testing physical page alloc/free...\n");
    uint32_t phys1 = alloc_phys_page();
    uint32_t phys2 = alloc_phys_page();
    printf("\t\tPhys1: 0x%x\n", phys1);
    printf("\t\tPhys2: 0x%x\n", phys2);
    free_phys_page(phys1);
    free_phys_page(phys2);
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
    map_page(0xC00000, 0x400000);
    printf("\t\tMapped 4MB at 0xC00000...\n");
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
    alloc_region(0x2000000, 8);
    printf("\t\tRegion allocated at 0x2000000\n");
    free_region(0x2000000, 8);
    printf("\t\tRegion freed.\n");
    alloc_region(0x2000000, 8);
    printf("\t\tRegion reallocated successfully.\n");
    free_region(0x2000000, 8);

    printf("TEST 7: Testing fragmentation...\n");
    map_page(0x3000000, 0x400000);
    map_page(0x7000000, 0x400000);
    unmap_page(0x3000000);
    map_page(0x5000000, 0x400000);
    unmap_page(0x7000000);
    unmap_page(0x5000000);
    printf("done.\n");
}

void test_ata_read(void)
{
    SuperBlock superblock;
    if (read_superblock(&superblock) != 0)
    {
        printf("Could not read superblock\n");
        return;
    }

    FileTable table;
    if (disk_read(superblock.file_table_sector, superblock.file_table_size, &table) != 0)
    {
        printf("Could not read file table\n");
        return;
    }

    int index = find_entry_by_path(&table, "/system/kernel.bin");
    if (index == -1)
    {
        printf("kernel.bin not found!\n");
        return;
    }

    FileEntry* entry = &table.entries[index];

    uint8_t buffer[512];
    if (ata_read(entry->start_sector, 1, buffer) == 0)
    {
        printf("kernel.bin start sector: %d\nFirst 16 bytes:\n", entry->start_sector);
        for (int i = 0; i < 16; i++)
        {
            printf("%x ", buffer[i]);
        }
        printf("\n");
    }
    else
    {
        printf("Failed to read kernel.bin sector!\n");
    }
}

