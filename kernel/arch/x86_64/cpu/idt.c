// idt.c

#include "idt.h"
#include "irq.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "system/syscall.h"
#include "system/process.h"

#define ISR_STUB(i) extern void isr##i(void);
#define XISR(n) ISR_STUB(n)
#define REPEAT32(X) \
     X(0)  X(1)  X(2)  X(3)  X(4)  X(5)  X(6)  X(7) \
     X(8)  X(9)  X(10) X(11) X(12) X(13) X(14) X(15)\
     X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23)\
     X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31)

REPEAT32(XISR)

#define XPTR(n) isr##n,
void *isr_stubs[32] = { REPEAT32(XPTR) };
#undef XPTR

struct IDTEntry idt[IDT_SIZE];
extern void system_call_init(void);

const char *exception_messages[] =
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

static inline uint32_t read_cr2(void){ uint32_t x; asm volatile("mov %%cr2,%0":"=r"(x)); return x; }
static inline uint32_t read_cr3(void){ uint32_t x; asm volatile("mov %%cr3,%0":"=r"(x)); return x; }

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

/* === Samma utskrift som förr, men körs nu på kernel-CR3 för att undvika PF i konsolen === */

static volatile int s_in_pf = 0;  // reentransvakt


static void print_page_fault(struct stack_frame *f, uint32_t cr2, uint32_t cr3, int handled)
{
    if (++s_in_pf > 1) {
        puts("\n==== PAGE FAULT (re-entrant) ====\n");
        printf("EIP=%08x  CR2=%08x\n", f->eip, cr2);
        for(;;) asm volatile("hlt");
    }

    // Skriv bara säkra saker: inga pekare-derefs, inget CR3-byte.
    puts("\n==== PAGE FAULT ====\n");
    printf("EIP=%08x  CR2=%08x  ERR=%08x  CR3=%08x%s\n",
           f->eip, cr2, f->err_code, cr3, handled ? "  [handled]" : "");

    dump_err_bits(f->err_code);

    printf("EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n", f->eax, f->ebx, f->ecx, f->edx);
    printf("ESI=%08x EDI=%08x EBP=%08x ESP=%08x\n", f->esi, f->edi, f->ebp, f->esp);

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

        printf("==== General Protection Fault ====\n");
        printf("EIP=%08x CS=%04x EFLAGS=%08x\n", frame->eip, frame->cs, frame->eflags);
        printf("CR3=%08x ERR=%08x (ext=%d, table=%s, %s, index=%u)\n",
               read_cr3_local(), err,
               ext, idt ? "IDT" : (ti ? "LDT" : "GDT"),
               ti ? "LDT" : "GDT", idx);
        printf("SS=%04x ESP=%08x DS=%04x ES=%04x FS=%04x GS=%04x\n",
               frame->ss, frame->useresp, frame->ds, frame->es, frame->fs, frame->gs);

        for(;;) asm volatile("hlt");
    }
    else if (frame->int_no == 14) { // #PF
        uint32_t cr2, cr3;
        asm volatile("mov %%cr2,%0" : "=r"(cr2));
        asm volatile("mov %%cr3,%0" : "=r"(cr3));

        // OBS: fältnamnet kan variera i din stack_frame.
        // Vanligt är 'err_code', men om ditt heter t.ex. 'error_code' eller 'err',
        // ändra raden nedan.
        uint32_t err = frame->err_code;

        int handled = paging_handle_page_fault(cr2, err);

        if (handled) 
        {
            return;
        }

        // Ohanterad -> skriv info och stoppa
        print_page_fault(frame, cr2, cr3, handled);
        for (;;)
            asm volatile("hlt");
    }


    puts(exception_messages[frame->int_no]);
    for(;;) asm volatile("hlt");
}

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

