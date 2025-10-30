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
#include "system/syscall.h"
#include "system/process.h"
#include "system/gdt.h"

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

extern char __heap_start;
extern char __heap_end;

static sys_info_t system;
static char background = BG_BLACK;
static char foreground = FG_GRAY;

static void init_thread(void* argument);
void display_banner(void);
void display_sys_info(void);

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
    
    gdt_init();
    init_paging(ram_mb);
    init_heap(&__heap_start, &__heap_end);

    process_init();
    idt_init();
    system_call_init();
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

static void init_thread(void* argument)
{
    (void)argument;
    
    vga_capture_rom_font_early();
    uint8_t h = vga_cell_height();
    vga_cursor_enable(0, h - 1);
    
    init_filesystem();
    display_banner();
    display_sys_info();

    char* system_config_file = "system/sys.cfg";

    int shell_spawn_state = 0;

    for (;;)
    {
        if (shell_spawn_state == 0)
        {
            load_drivers(file_table, system_config_file);

            char* shell_path = find_shell_path(file_table, system_config_file);

            if (!shell_path)
            {
                printf("[CRITICAL ERROR] No shell was set!\n");
                shell_spawn_state = -1;  
            }
            else
            {
                int pid = dex_spawn_process(file_table, shell_path, 0, 0);
                kfree(shell_path);

                if (pid > 0)
                {
                    shell_spawn_state = 1;
                }
                else
                {
                    printf("[KERNEL] Failed to spawn shell (pid=%d). Not retrying.\n", pid);
                    shell_spawn_state = -1;
                }
            }
        }

        thread_yield();
    }
}

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

