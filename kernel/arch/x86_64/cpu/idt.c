// idt.c (PF-säker variant som loggar via rå serieport)

#include "idt.h"
#include "irq.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "system/syscall.h"
#include "system/process.h"
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
static inline void panic_putu32(uint32_t v) {
    char buf[11]; int i = 0;
    if (v == 0) { panic_putc('0'); return; }
    while (v && i < 10) { buf[i++] = '0' + (v % 10); v /= 10; }
    while (i--) panic_putc(buf[i]);
}
static inline void panic_putreg(const char *name, uint32_t v) {
    panic_puts(name); panic_putc('='); panic_puthex32(v); panic_putc(' ');
}

// =====================================================================
//                           FAULT HANDLING
// =====================================================================

static volatile int s_in_pf = 0;  // reentransvakt

// PF-utskrift som INTE kan pagefaulta (ingen printf/heap/lås)
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

    // Register
    panic_putreg("EAX", f->eax); panic_putreg("EBX", f->ebx);
    panic_putreg("ECX", f->ecx); panic_putreg("EDX", f->edx); panic_puts("\n");
    panic_putreg("ESI", f->esi); panic_putreg("EDI", f->edi);
    panic_putreg("EBP", f->ebp); panic_putreg("ESP", f->esp); panic_puts("\n");

    --s_in_pf;
}

void fault_handler(struct stack_frame *frame)
{
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

        panic_puts("SS="); panic_puthex32(frame->ss);
        panic_puts(" ESP="); panic_puthex32(frame->useresp);
        panic_puts(" DS="); panic_puthex32(frame->ds);
        panic_puts(" ES="); panic_puthex32(frame->es);
        panic_puts(" FS="); panic_puthex32(frame->fs);
        panic_puts(" GS="); panic_puthex32(frame->gs);
        panic_puts("\n");

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
        panic_puts("int_no="); panic_putu32(frame->int_no);
        panic_puts("\n");
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

