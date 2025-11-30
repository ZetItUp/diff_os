// idt.c (PF-säker variant som loggar via rå serieport)

#include "idt.h"
#include "irq.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "system/syscall.h"
#include "system/process.h"
#include "debug.h"
#include "system/usercopy.h"
#include <stdint.h>

// ===== ISR stubs =====
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

// (Referenslista – används inte i panikutskrifter)
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

// ===== CRx helpers =====
static inline uint32_t read_cr2(void){ uint32_t x; asm volatile("mov %%cr2,%0":"=r"(x)); return x; }
static inline uint32_t read_cr3(void){ uint32_t x; asm volatile("mov %%cr3,%0":"=r"(x)); return x; }

// ===== IDT setup =====
void idt_set_entry(int num, uint32_t handler_addr, uint16_t selector, uint8_t type_attr)
{
    idt[num].offset_low  = (handler_addr & 0xFFFF);
    idt[num].selector    = selector;
    idt[num].zero        = 0;
    idt[num].type_attr   = type_attr;  // 0x8E = present, ring0, 32-bit interrupt gate
    idt[num].offset_high = (handler_addr >> 16) & 0xFFFF;
}

void idt_init(void)
{
    for (int i = 0; i < 32; i++)
        idt_set_entry(i, (uint32_t)isr_stubs[i], 0x08, 0x8E);

    struct IDTDescriptor idt_desc;
    idt_desc.limit = sizeof(idt) - 1;
    idt_desc.base  = (uint32_t)&idt;

    asm volatile("cli");
    asm volatile("lidt %0" : : "m"(idt_desc));
    system_call_init();
}

// =====================================================================
//                   RAW SERIAL "PANIC" PRINT (PF-SAFE)
// =====================================================================

static inline void outb(uint16_t port, uint8_t val) { asm volatile("outb %0,%1"::"a"(val),"Nd"(port)); }
static inline uint8_t inb(uint16_t port) { uint8_t r; asm volatile("inb %1,%0":"=a"(r):"Nd"(port)); return r; }

#define COM1_BASE 0x3F8

static inline void panic_serial_init(void)
{
    // Snabb init av COM1 115200 8N1, inga avbrott
    outb(COM1_BASE + 1, 0x00);    // IER: disable interrupts
    outb(COM1_BASE + 3, 0x80);    // LCR: enable DLAB
    outb(COM1_BASE + 0, 0x01);    // DLL: divisor low (115200)
    outb(COM1_BASE + 1, 0x00);    // DLH: divisor high
    outb(COM1_BASE + 3, 0x03);    // LCR: 8N1, DLAB=0
    outb(COM1_BASE + 2, 0xC7);    // FCR: enable FIFO, clear, 14-byte threshold
    outb(COM1_BASE + 4, 0x0B);    // MCR: DTR, RTS, OUT2
}

static inline void serial_putc(char c) {
    while ((inb(COM1_BASE + 5) & 0x20) == 0) { } // vänta tills THR tom
    outb(COM1_BASE, (uint8_t)c);
}
static inline void panic_putc(char c) {
    if (c == '\n') serial_putc('\r');
    serial_putc(c);
}
static inline void panic_puts(const char *s) {
    while (*s) panic_putc(*s++);
}
static inline void panic_puthex32(uint32_t v) {
    static const char *hex = "0123456789ABCDEF";
    for (int i = 7; i >= 0; --i) {
        uint8_t nib = (v >> (i*4)) & 0xF;
        panic_putc(hex[nib]);
    }
}
static inline void panic_puthex8(uint8_t v) {
    static const char *hex = "0123456789ABCDEF";
    panic_putc(hex[(v >> 4) & 0xF]);
    panic_putc(hex[v & 0xF]);
}
static inline void panic_putu32(uint32_t v) {
    char buf[11]; int i = 0;
    if (v == 0) { panic_putc('0'); return; }
    while (v && i < 10) { buf[i++] = '0' + (v % 10); v /= 10; }
    while (i--) panic_putc(buf[i]);
}
static inline void panic_putreg(const char *name, uint32_t v) {
    panic_puts(name); panic_putc('='); panic_puthex32(v); panic_putc(' ');
}

static void panic_print_cpu_context(const struct stack_frame *f)
{
    panic_putreg("EAX", f->eax); panic_putreg("EBX", f->ebx);
    panic_putreg("ECX", f->ecx); panic_putreg("EDX", f->edx); panic_puts("\n");
    panic_putreg("ESI", f->esi); panic_putreg("EDI", f->edi);
    panic_putreg("EBP", f->ebp); panic_putreg("ESP", f->esp); panic_puts("\n");

    panic_puts("CS="); panic_puthex32(f->cs);
    panic_puts(" DS="); panic_puthex32(f->ds);
    panic_puts(" ES="); panic_puthex32(f->es);
    panic_puts(" FS="); panic_puthex32(f->fs);
    panic_puts(" GS="); panic_puthex32(f->gs);
    panic_puts(" SS="); panic_puthex32(f->ss);
    panic_puts("\n");

    panic_puts("EIP="); panic_puthex32(f->eip);
    panic_puts(" EFLAGS="); panic_puthex32(f->eflags);
    panic_puts(" USERESP="); panic_puthex32(f->useresp);
    panic_puts("\n");
}

static void panic_print_process_info(void)
{
    process_t *p = process_current();
    panic_puts("PID=");
    if (p)
    {
        panic_putu32((uint32_t)p->pid);
        panic_puts(" CR3=");
        panic_puthex32(p->cr3);
    }
    else
    {
        panic_puts("none");
    }
    panic_puts("\n");
}

static void panic_dump_code_window(uint32_t center, size_t pre, size_t post)
{
    uint32_t start = center;
    if (center > pre)
    {
        start -= (uint32_t)pre;
    }
    else
    {
        start = 0;
    }

    size_t total = pre + post;

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

        uint8_t val = 0;
        int rc = 0;
        if (addr >= KERNEL_BASE)
        {
            val = *(const uint8_t *)(uintptr_t)addr;
        }
        else
        {
            rc = copy_from_user(&val, (const void *)(uintptr_t)addr, 1);
        }

        if (rc != 0)
        {
            panic_puts("?? ");
            continue;
        }

        if (addr == center)
        {
            panic_putc('[');
            panic_puthex8(val);
            panic_putc(']');
        }
        else
        {
            panic_puthex8(val);
        }
        panic_putc(' ');
    }
    panic_puts("\n");
}

// =====================================================================
//                           FAULT HANDLING
// =====================================================================

static volatile int s_in_pf = 0;  // reentransvakt

// PF-utskrift som INTE kan pagefaulta (ingen printf/heap/lås)
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

static void print_page_fault(struct stack_frame *f, uint32_t cr2, uint32_t cr3, int handled)
{
    // Re-entrant PF -> skriv minsta möjliga och stoppa hårt
    if (++s_in_pf > 1) {
        panic_serial_init();
        panic_puts("\n[PF] re-entrant, halting.\n");
        for(;;) asm volatile("hlt");
    }

    panic_serial_init();

    panic_puts("\n==== PAGE FAULT ====\n");
    panic_puts("EIP="); panic_puthex32(f->eip);
    panic_puts("  CR2="); panic_puthex32(cr2);
    panic_puts("  ERR="); panic_puthex32(f->err_code);
    panic_puts("  CR3="); panic_puthex32(cr3);
    if (handled) panic_puts("  [handled]");
    panic_puts("\n");

    // Kort err-bits
    uint32_t err = f->err_code;
    panic_puts(" P=");  panic_putu32((err>>0)&1);
    panic_puts(" W=");  panic_putu32((err>>1)&1);
    panic_puts(" U=");  panic_putu32((err>>2)&1);
    panic_puts(" RSVD="); panic_putu32((err>>3)&1);
    panic_puts(" IF="); panic_putu32((err>>4)&1);
    panic_puts("\n");

    panic_print_cpu_context(f);
    panic_print_process_info();
    print_user_stack_snapshot(f->useresp);
    --s_in_pf;
}

void fault_handler(struct stack_frame *frame)
{
    if (frame->int_no == 1)
    {
        if (debug_handle_single_step(frame)) return;
    }

    if (frame->int_no >= 32) return;

    if (frame->int_no == 13) // #GP
    {
        uint32_t err = frame->err_code;
        uint32_t idx = (err >> 3) & 0x1FFF;
        int ext = err & 1;
        int idt = (err >> 1) & 1;
        int ti  = (err >> 2) & 1;

        panic_serial_init();
        panic_puts("==== General Protection Fault ====\n");
        panic_puts("EIP="); panic_puthex32(frame->eip);
        panic_puts(" CS="); panic_puthex32(frame->cs);
        panic_puts(" EFLAGS="); panic_puthex32(frame->eflags); panic_puts("\n");

        panic_puts("CR3="); panic_puthex32(read_cr3());
        panic_puts(" ERR="); panic_puthex32(err);
        panic_puts(" (ext="); panic_putu32(ext);
        panic_puts(", table="); panic_puts(idt ? "IDT" : (ti ? "LDT" : "GDT"));
        panic_puts(", "); panic_puts(ti ? "LDT" : "GDT");
        panic_puts(", index="); panic_putu32(idx); panic_puts(")\n");

        panic_print_cpu_context(frame);
        panic_print_process_info();

        for(;;) asm volatile("hlt");
    }
    else if (frame->int_no == 14) { // #PF
        uint32_t cr2, cr3;
        asm volatile("mov %%cr2,%0" : "=r"(cr2));
        asm volatile("mov %%cr3,%0" : "=r"(cr3));

        uint32_t err = frame->err_code;
        int handled = paging_handle_page_fault(cr2, err);
        if (handled) {
            return;
        }

        // Ohanterad -> skriv info och stoppa
        print_page_fault(frame, cr2, cr3, handled);
        for (;;)
            asm volatile("hlt");
    }
    else
    {
        // Fallback: minimal serial och häng (PF-säkert)
        panic_serial_init();
        panic_puts("==== CPU EXCEPTION ====\n");
        panic_puts("Vector=");
        panic_putu32(frame->int_no);
        panic_puts(" (");
        if (frame->int_no < 32)
            panic_puts(exception_messages[frame->int_no]);
        else
            panic_puts("Unknown");
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
        for(;;) asm volatile("hlt");
    }
}

// Endast för icke-panik: använder vanlig konsol
void dump_idt(void)
{
    puts("IDT ENTRIES:\n");
    for (int i = 0; i < 20; i++) {
        uint32_t handler = (idt[i].offset_high << 16) | idt[i].offset_low;
        puts("IDT[");
        puthex(i);
        puts("] = 0x");
        puthex(handler);
        puts("\n");
    }
}
