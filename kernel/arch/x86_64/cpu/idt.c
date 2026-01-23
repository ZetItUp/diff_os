// idt file with PF safe logging via raw serial

#include "idt.h"
#include "irq.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "system/syscall.h"
#include "system/process.h"
#include "system/signal.h"
#include "debug.h"
#include "system/usercopy.h"
#include <stdint.h>

// ISR stubs
#define ISR_STUB(i) extern void isr##i(void);
#define XISR(n) ISR_STUB(n)
#define REPEAT32(X) \
     X(0)  X(1)  X(2)  X(3)  X(4)  X(5)  X(6)  X(7) \
     X(8)  X(9)  X(10) X(11) X(12) X(13) X(14) X(15)\
     X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23)\
     X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)
REPEAT32(XISR)
#undef XISR

#define XPTR(n) isr##n,
void *isr_stubs[32] = { REPEAT32(XPTR) };
#undef XPTR

struct IDTEntry idt[IDT_SIZE];
extern void system_call_init(void);

// Reference list
static const char *exception_messages[] =
{
    "Division By Zero",            // 0
    "Debug",                       // 1
    "Non Maskable Interrupt",      // 2
    "Breakpoint",                  // 3
    "Overflow",                    // 4
    "Bound Range Exceeded",        // 5
    "Invalid Opcode",              // 6
    "Device Not Available",        // 7
    "Double Fault",                // 8
    "Coprocessor Segment Overrun", // 9
    "Invalid TSS",                 // 10
    "Segment Not Present",         // 11
    "Stack Segment Fault",         // 12
    "General Protection Fault",    // 13
    "Page Fault",                  // 14
    "Reserved",                    // 15
    "x87 Floating Point Exception",// 16
    "Alignment Check",             // 17
    "Machine Check",               // 18
    "SIMD Floating Point Exception",// 19
    "Virtualization Exception",    // 20
    "Control Protection Exception",// 21
    "Reserved", "Reserved", "Reserved", "Reserved",
    "Reserved", "Reserved", "Reserved", "Reserved"
};

// CRx helpers
static inline uint32_t read_cr2(void)
{
    uint32_t cr2;
    asm volatile("mov %%cr2,%0" : "=r"(cr2));

    return cr2;
}

static inline uint32_t read_cr3(void)
{
    uint32_t cr3;
    asm volatile("mov %%cr3,%0" : "=r"(cr3));

    return cr3;
}

// IDT setup
void idt_set_entry(
    int entry_index,
    uint32_t handler_address,
    uint16_t selector,
    uint8_t type_attributes)
{
    idt[entry_index].offset_low = (handler_address & 0xFFFF);
    idt[entry_index].selector = selector;
    idt[entry_index].zero = 0;
    idt[entry_index].type_attr = type_attributes;
    idt[entry_index].offset_high = (handler_address >> 16) & 0xFFFF;
}

void idt_init(void)
{
    for (int i = 0; i < 32; i++)
    {
        idt_set_entry(i, (uint32_t)isr_stubs[i], 0x08, 0x8E);
    }

    struct IDTDescriptor idt_desc;
    idt_desc.limit = sizeof(idt) - 1;
    idt_desc.base = (uint32_t)&idt;

    asm volatile("cli");
    asm volatile("lidt %0" : : "m"(idt_desc));
    system_call_init();
}

// Raw serial panic print PF safe
static inline void outb(uint16_t port, uint8_t value)
{
    asm volatile("outb %0,%1"::"a"(value),"Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t value;
    asm volatile("inb %1,%0":"=a"(value):"Nd"(port));

    return value;
}

#define COM1_BASE 0x3F8

static inline void panic_serial_init(void)
{
    // Quick init for COM1 115200 8N1 and no interrupts
    outb(COM1_BASE + 1, 0x00);
    outb(COM1_BASE + 3, 0x80);
    outb(COM1_BASE + 0, 0x01);
    outb(COM1_BASE + 1, 0x00);
    outb(COM1_BASE + 3, 0x03);
    outb(COM1_BASE + 2, 0xC7);
    outb(COM1_BASE + 4, 0x0B);
}

static inline void serial_putc(char c)
{
    while ((inb(COM1_BASE + 5) & 0x20) == 0)
    {
    }

    outb(COM1_BASE, (uint8_t)c);
}

static inline void panic_putc(char c)
{
    if (c == '\n')
    {
        serial_putc('\r');
    }

    serial_putc(c);
}

static inline void panic_puts(const char *text)
{
    while (*text)
    {
        panic_putc(*text++);
    }
}

static inline void panic_puthex32(uint32_t value)
{
    static const char *hex = "0123456789ABCDEF";

    for (int i = 7; i >= 0; --i)
    {
        uint8_t nibble = (value >> (i * 4)) & 0xF;
        panic_putc(hex[nibble]);
    }
}

static inline void panic_puthex8(uint8_t value)
{
    static const char *hex = "0123456789ABCDEF";
    panic_putc(hex[(value >> 4) & 0xF]);
    panic_putc(hex[value & 0xF]);
}

static inline void panic_putu32(uint32_t value)
{
    char buf[11];
    int i = 0;

    if (value == 0)
    {
        panic_putc('0');

        return;
    }

    while (value && i < 10)
    {
        buf[i++] = '0' + (value % 10);
        value /= 10;
    }

    while (i--)
    {
        panic_putc(buf[i]);
    }
}

static inline void panic_putreg(const char *name, uint32_t value)
{
    panic_puts(name);
    panic_putc('=');
    panic_puthex32(value);
    panic_putc(' ');
}

static void panic_print_cpu_context(const struct stack_frame *frame)
{
    panic_putreg("EAX", frame->eax);
    panic_putreg("EBX", frame->ebx);
    panic_putreg("ECX", frame->ecx);
    panic_putreg("EDX", frame->edx);
    panic_puts("\n");
    panic_putreg("ESI", frame->esi);
    panic_putreg("EDI", frame->edi);
    panic_putreg("EBP", frame->ebp);
    panic_putreg("ESP", frame->esp);
    panic_puts("\n");

    panic_puts("CS=");
    panic_puthex32(frame->cs);
    panic_puts(" DS=");
    panic_puthex32(frame->ds);
    panic_puts(" ES=");
    panic_puthex32(frame->es);
    panic_puts(" FS=");
    panic_puthex32(frame->fs);
    panic_puts(" GS=");
    panic_puthex32(frame->gs);
    panic_puts(" SS=");
    panic_puthex32(frame->ss);
    panic_puts("\n");

    panic_puts("EIP=");
    panic_puthex32(frame->eip);
    panic_puts(" EFLAGS=");
    panic_puthex32(frame->eflags);
    panic_puts(" USERESP=");
    panic_puthex32(frame->useresp);
    panic_puts("\n");
}

static void panic_print_process_info(void)
{
    process_t *process = process_current();
    panic_puts("PID=");

    if (process)
    {
        panic_putu32((uint32_t)process->pid);
        panic_puts(" CR3=");
        panic_puthex32(process->cr3);
    }
    else
    {
        panic_puts("none");
    }

    panic_puts("\n");
}

static void panic_dump_code_window(uint32_t center, size_t pre_bytes, size_t post_bytes)
{
    uint32_t start = center;

    if (center > pre_bytes)
    {
        start -= (uint32_t)pre_bytes;
    }
    else
    {
        start = 0;
    }

    size_t total = pre_bytes + post_bytes;

    panic_puts("Code bytes around fault:\n");

    for (size_t i = 0; i < total; ++i)
    {
        uint32_t addr = start + (uint32_t)i;

        if ((i & 0x0Fu) == 0)
        {
            panic_puts("  ");
            panic_puthex32(addr);
            panic_puts(": ");
        }

        uint8_t value = 0;
        int result = 0;

        if (addr >= KERNEL_BASE)
        {
            value = *(const uint8_t *)(uintptr_t)addr;
        }
        else
        {
            result = copy_from_user(&value, (const void *)(uintptr_t)addr, 1);
        }

        if (result != 0)
        {
            panic_puts("?? ");

            continue;
        }

        if (addr == center)
        {
            panic_putc('[');
            panic_puthex8(value);
            panic_putc(']');
        }
        else
        {
            panic_puthex8(value);
        }

        panic_putc(' ');
    }

    panic_puts("\n");
}

// Fault handling
static volatile int s_in_page_fault = 0; // reentrancy guard
static int s_pf_streak_pid = -1;
static uint32_t s_pf_streak_count;

// PF output that does not page fault
static void print_user_stack_snapshot(uint32_t useresp)
{
    const int stack_words = 8;
    uint32_t stack[stack_words];

    if (paging_check_user_range(useresp, stack_words * sizeof(uint32_t)) != 0)
    {
        panic_puts("User stack snapshot unavailable\n");

        return;
    }

    if (copy_from_user(stack, (const void *)(uintptr_t)useresp,
                       stack_words * sizeof(uint32_t)) != 0)
    {
        panic_puts("User stack snapshot failed\n");

        return;
    }

    panic_puts("User stack @");
    panic_puthex32(useresp);
    panic_putc(':');

    for (int i = 0; i < stack_words; ++i)
    {
        panic_putc(' ');
        panic_puthex32(stack[i]);
    }

    panic_puts("\n");
}

static void print_page_fault(struct stack_frame *frame, uint32_t cr2, uint32_t cr3, int handled)
{
    // Reentrant PF prints the minimum and halts
    if (++s_in_page_fault > 1)
    {
        panic_serial_init();
        panic_puts("\n[PF] re-entrant, halting.\n");

        for (;;)
        {
            asm volatile("hlt");
        }
    }

    panic_serial_init();

    panic_puts("\n==== PAGE FAULT ====\n");
    panic_puts("EIP=");
    panic_puthex32(frame->eip);
    panic_puts("  CR2=");
    panic_puthex32(cr2);
    panic_puts("  ERR=");
    panic_puthex32(frame->err_code);
    panic_puts("  CR3=");
    panic_puthex32(cr3);

    if (handled)
    {
        panic_puts("  [handled]");
    }

    panic_puts("\n");

    uint32_t error_code = frame->err_code;
    panic_puts(" P=");
    panic_putu32((error_code >> 0) & 1);
    panic_puts(" W=");
    panic_putu32((error_code >> 1) & 1);
    panic_puts(" U=");
    panic_putu32((error_code >> 2) & 1);
    panic_puts(" RSVD=");
    panic_putu32((error_code >> 3) & 1);
    panic_puts(" IF=");
    panic_putu32((error_code >> 4) & 1);
    panic_puts("\n");

    panic_print_cpu_context(frame);
    panic_print_process_info();
    print_user_stack_snapshot(frame->useresp);

    s_in_page_fault--;
}

void fault_handler(struct stack_frame *frame)
{
    int is_user_mode = ((frame->cs & 3u) == 3u);

    if (frame->int_no < 32)
    {
        panic_serial_init();
        panic_puts("EXC ");
        panic_putu32(frame->int_no);
        panic_puts(" EIP=");
        panic_puthex32(frame->eip);
        panic_puts("\n");
    }

    if (frame->int_no == 8)
    {
        panic_serial_init();
        panic_puts("==== DOUBLE FAULT ====\n");
        panic_puts("EIP=");
        panic_puthex32(frame->eip);
        panic_puts(" CS=");
        panic_puthex32(frame->cs);
        panic_puts(" EFLAGS=");
        panic_puthex32(frame->eflags);
        panic_puts("\n");
        panic_puts("ERR=");
        panic_puthex32(frame->err_code);
        panic_puts(" CR3=");
        panic_puthex32(read_cr3());
        panic_puts("\n");
        panic_print_cpu_context(frame);
        panic_print_process_info();

        for (;;)
        {
            asm volatile("hlt");
        }
    }

    if (frame->int_no == 1)
    {
        if (debug_handle_single_step(frame))
        {
            return;
        }
    }

    if (frame->int_no >= 32)
    {
        return;
    }

    if (frame->int_no == 13)
    {
        if (is_user_mode)
        {
            signal_send_to_process(process_current(), SIGSEGV);
            signal_maybe_deliver_frame(process_current(), frame);

            return;
        }

        uint32_t error_code = frame->err_code;
        uint32_t descriptor_index = (error_code >> 3) & 0x1FFF;
        int is_external = error_code & 1;
        int is_idt = (error_code >> 1) & 1;
        int table_indicator = (error_code >> 2) & 1;

        panic_serial_init();
        panic_puts("==== General Protection Fault ====\n");
        panic_puts("EIP=");
        panic_puthex32(frame->eip);
        panic_puts(" CS=");
        panic_puthex32(frame->cs);
        panic_puts(" EFLAGS=");
        panic_puthex32(frame->eflags);
        panic_puts("\n");

        panic_puts("CR3=");
        panic_puthex32(read_cr3());
        panic_puts(" ERR=");
        panic_puthex32(error_code);
        panic_puts(" (ext=");
        panic_putu32(is_external);
        panic_puts(", table=");
        panic_puts(is_idt ? "IDT" : (table_indicator ? "LDT" : "GDT"));
        panic_puts(", ");
        panic_puts(table_indicator ? "LDT" : "GDT");
        panic_puts(", index=");
        panic_putu32(descriptor_index);
        panic_puts(")\n");

        panic_print_cpu_context(frame);
        panic_print_process_info();

        for (;;)
        {
            asm volatile("hlt");
        }
    }
    else if (frame->int_no == 14)
    {
        uint32_t cr2;
        uint32_t cr3;
        asm volatile("mov %%cr2,%0" : "=r"(cr2));
        asm volatile("mov %%cr3,%0" : "=r"(cr3));

        uint32_t error_code = frame->err_code;
        int handled = paging_handle_page_fault(cr2, error_code);

        if (handled)
        {
            if (is_user_mode)
            {
                process_t *proc = process_current();
                int pid = proc ? proc->pid : -1;
                if (pid == s_pf_streak_pid)
                {
                    s_pf_streak_count++;
                }
                else
                {
                    s_pf_streak_pid = pid;
                    s_pf_streak_count = 0;
                }

                if (s_pf_streak_count > 2048)
                {
                    panic_serial_init();
                    panic_puts("PF storm PID=");
                    panic_putu32(pid < 0 ? 0u : (uint32_t)pid);
                    panic_puts(" EIP=");
                    panic_puthex32(frame->eip);
                    panic_puts(" CR2=");
                    panic_puthex32(cr2);
                    panic_puts(" ERR=");
                    panic_puthex32(error_code);
                    panic_puts("\n");
                    process_exit_current(128 + SIGSEGV);
                }
            }

            return;
        }

        if (is_user_mode)
        {
            process_t *proc = process_current();
            panic_serial_init();
            panic_puts("[PF-USER] PID=");
            panic_putu32(proc ? (uint32_t)proc->pid : 0);
            panic_puts(" CR2=");
            panic_puthex32(cr2);
            panic_puts(" EIP=");
            panic_puthex32(frame->eip);
            panic_puts(" ERR=");
            panic_puthex32(error_code);
            panic_puts("\n");

            signal_send_to_process(proc, SIGSEGV);
            signal_maybe_deliver_frame(proc, frame);

            return;
        }

        // Unhandled page fault prints info and halts
        print_page_fault(frame, cr2, cr3, handled);

        for (;;)
        {
            asm volatile("hlt");
        }
    }
    else
    {
        if (is_user_mode)
        {
            int signal_number = 0;
            switch (frame->int_no)
            {
                case 0:
                    signal_number = SIGFPE;

                    break;
                case 6:
                    signal_number = SIGILL;

                    break;
                case 8:
                    signal_number = SIGSEGV;

                    break;
                case 10:
                    signal_number = SIGSEGV;

                    break;
                case 11:
                    signal_number = SIGSEGV;

                    break;
                case 12:
                    signal_number = SIGSEGV;

                    break;
                default:
                    signal_number = SIGILL;

                    break;
            }

            signal_send_to_process(process_current(), signal_number);
            signal_maybe_deliver_frame(process_current(), frame);

            return;
        }

        // Fallback uses minimal serial and halts
        panic_serial_init();
        panic_puts("==== CPU EXCEPTION ====\n");
        panic_puts("Vector=");
        panic_putu32(frame->int_no);
        panic_puts(" (");

        if (frame->int_no < 32)
        {
            panic_puts(exception_messages[frame->int_no]);
        }
        else
        {
            panic_puts("Unknown");
        }

        panic_puts(")\n");

        panic_puts("ERR=");
        panic_puthex32(frame->err_code);
        panic_puts(" CR3=");
        panic_puthex32(read_cr3());
        panic_puts("\n");

        if (frame->int_no == 6)
        {
            panic_dump_code_window(frame->eip, 16, 32);
        }

        panic_print_cpu_context(frame);
        panic_print_process_info();

        for (;;)
        {
            asm volatile("hlt");
        }
    }
}

// Only for non panic use
void dump_idt(void)
{
    puts("IDT ENTRIES:\n");

    for (int i = 0; i < 20; i++)
    {
        uint32_t handler = (idt[i].offset_high << 16) | idt[i].offset_low;
        puts("IDT[");
        puthex(i);
        puts("] = 0x");
        puthex(handler);
        puts("\n");
    }
}
