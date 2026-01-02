#include "stdio.h"
#include "idt.h"
#include "string.h"
#include "paging.h"
#include "console.h"
#include "serial.h"
#include "irq.h"
#include "pic.h"
#include "apic.h"
#include "pci.h"
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
#include "drivers/device.h"
#include "dex/dex.h"
#include "system/threads.h"
#include "system/scheduler.h"
#include "system/syscall.h"
#include "system/process.h"

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
    serial_write("[KERNEL] kmain entered\n");

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
    device_registry_init();
    
    display_banner();
    pci_init();
    process_init();
    idt_init();
    system_call_init();

    // Try to use APIC if supported, otherwise fall back to PIC
    if (apic_is_supported())
    {
        printf("[KERNEL] APIC supported, using APIC mode\n");
        pic_remap(0x20, 0x28);  // Still remap PIC before disabling it
        pic_disable();          // Disable PIC
        apic_init();            // Initialize Local APIC
        ioapic_init();          // Initialize I/O APIC
        irq_init();             // Setup IDT entries
        irq_set_use_apic(1);    // Use APIC for EOI

        // Map legacy IRQs through I/O APIC
        // Note: IRQ0 (PIT timer) is not used when APIC timer is active
        ioapic_map_irq(0, 32, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // Timer (PIT, not used)
        ioapic_map_irq(1, 33, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // Keyboard
        ioapic_map_irq(2, 34, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // Cascade
        ioapic_map_irq(3, 35, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // COM2
        ioapic_map_irq(4, 36, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // COM1
        ioapic_map_irq(5, 37, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // LPT2
        ioapic_map_irq(6, 38, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // Floppy
        ioapic_map_irq(7, 39, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // LPT1
        ioapic_map_irq(8, 40, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // RTC
        ioapic_map_irq(9, 41, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH);  // ACPI
        ioapic_map_irq(10, 42, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // Available
        ioapic_map_irq(11, 43, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // Available
        ioapic_map_irq(12, 44, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // PS/2 Mouse
        ioapic_map_irq(13, 45, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // FPU
        ioapic_map_irq(14, 46, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // Primary ATA
        ioapic_map_irq(15, 47, IOAPIC_TRIGGER_EDGE | IOAPIC_POLARITY_HIGH); // Secondary ATA

        timer_install_apic();   // Install APIC timer handler first
        apic_timer_init(100);  // Initialize and start APIC timer at 100 Hz for smoother timing

        // Unmask keyboard (IRQ1) and mouse (IRQ12) so PS/2 input works in APIC mode
        ioapic_unmask_irq(1);
        ioapic_unmask_irq(12);
    }
    else
    {
        printf("[KERNEL] APIC not supported, using PIC mode\n");
        pic_remap(0x20, 0x28);
        irq_init();
        timer_install();        // Use PIT timer
    }

    scheduler_init();
    thread_create(init_thread, NULL, 32 * 1024);

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
                int pid = dex_spawn_process(file_table, shell_path, 0, 0, "/", 0);
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
    printf("OS\n\n");
    set_color(MAKE_COLOR(FG_GRAY, BG_BLACK));
    set_pos(x, y);
}

void display_sys_info(void)
{
    printf("[RAM] Available Memory: %u MB\n", system.ram_mb);
}
