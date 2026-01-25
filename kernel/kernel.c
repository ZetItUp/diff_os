#include "stdio.h"
#include "idt.h"
#include "paging.h"
#include "console.h"
#include "serial.h"
#include "irq.h"
#include "pic.h"
#include "apic.h"
#include "pci.h"
#include "timer.h"
#include "stdint.h"
#include "heap.h"
#include "diff.h"
#include "system.h"
#include "graphics/vbe_text.h"
#include "drivers/config.h"
#include "drivers/ipv4_config.h"
#include "drivers/device.h"
#include "dex/dex.h"
#include "system/threads.h"
#include "system/scheduler.h"
#include "system/syscall.h"
#include "system/process.h"
#include "system/irqsw.h"
#include "system/profiler.h"
#include "shared_kernel_data.h"
#include "multiboot.h"
#include "cpu.h"

extern char __heap_start;
extern char __heap_end;

static sys_info_t system;
static char background = BG_BLACK;
static char foreground = FG_GRAY;

static void init_thread(void);
void display_banner(void);
void display_sys_info(void);
static void capture_module_info(multiboot_info_t* mbi);
static void init_module_fs(void);

void kmain(uint32_t magic, multiboot_info_t* mbi)
{
    serial_init();

    set_color(MAKE_COLOR(foreground, background));
    clear();
    // Verify multiboot magic
    if (magic != MULTIBOOT_MAGIC)
    {
        serial_write("ERROR: Invalid multiboot magic!\n");
        printf("ERROR: Invalid multiboot magic: 0x%x\n", magic);

        for (;;)
        {
            asm volatile("hlt");
        }
    }

    capture_module_info(mbi);

    // Calculate total RAM from multiboot memory map
    uint32_t total_ram = 0;

    if (mbi->flags & MULTIBOOT_INFO_MMAP)
    {
        uint32_t offset = 0;

        while (offset < mbi->mmap_length)
        {
            multiboot_mmap_entry_t* entry = (multiboot_mmap_entry_t*)(mbi->mmap_addr + offset);

            if (entry->type == MULTIBOOT_MEMORY_AVAILABLE)
            {
                // Only count memory below 4GB
                if ((entry->base >> 32) == 0)
                {
                    uint64_t end = entry->base + entry->length;

                    if (end > 0xFFFFFFFF)
                    {
                        end = 0xFFFFFFFF;
                    }

                    total_ram += (uint32_t)(end - entry->base);
                }
            }

            offset += entry->size + sizeof(entry->size);
        }
    }
    else if (mbi->flags & MULTIBOOT_INFO_MEMORY)
    {
        // Fallback using mem_upper in KB above 1MB
        total_ram = (mbi->mem_upper + 1024) * 1024;
    }

    uint32_t ram_mb = (uint32_t)(total_ram / (1024 * 1024));
    system.ram_mb = ram_mb;

    init_paging(ram_mb);
    init_module_fs();  // Reserve and set up module after paging is initialized
    cpu_init();
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
        printf("APIC supported, using APIC mode\n");
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

        // Unmask IRQ11 for PCI network devices like RTL8139
        ioapic_unmask_irq(11);
    }
    else
    {
        printf("APIC not supported, using PIC mode\n");
        pic_remap(0x20, 0x28);
        irq_init();
        timer_install();        // Use PIT timer
    }

    scheduler_init();
    irqsw_init();
    shared_kernel_data_init();
    profiler_init();
    thread_create(init_thread, NULL, 32 * 1024);

    asm volatile("sti");
    scheduler_start();

    for (;;)
    {
    }
}

static void init_thread(void)
{
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
            ipv4_config_load(file_table, "system/network/ipv4.cfg");
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
                    printf("Failed to spawn shell (pid=%d). Not retrying.\n", pid);
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

// Module info storage - captured early, reserved after paging init
static uint32_t s_module_start = 0;
static uint32_t s_module_size = 0;

// Capture module info from multiboot (called before init_paging)
static void capture_module_info(multiboot_info_t* mbi)
{
    if (!mbi)
    {
        return;
    }

    if ((mbi->flags & MULTIBOOT_INFO_MODS) == 0)
    {
        return;
    }

    if (mbi->mods_count == 0)
    {
        return;
    }

    multiboot_module_t* mods = (multiboot_module_t*)(uintptr_t)mbi->mods_addr;
    uint32_t start = mods[0].mod_start;
    uint32_t end = mods[0].mod_end;

    if (end <= start)
    {
        printf("Module range invalid start=0x%x end=0x%x\n", start, end);
        return;
    }

    s_module_start = start;
    s_module_size = end - start;
}

// Set up module filesystem (called after init_paging to reserve physical pages)
static void init_module_fs(void)
{
    if (s_module_start == 0 || s_module_size == 0)
    {
        return;
    }

    // Reserve the module's physical memory so it won't be allocated to processes
    paging_reserve_phys_range(s_module_start, s_module_size);

    // Now set up the module for filesystem access
    diff_set_module_image((const void*)(uintptr_t)s_module_start, s_module_size);
}
