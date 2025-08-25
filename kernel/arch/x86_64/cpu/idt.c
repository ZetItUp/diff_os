// idt.c

#include "idt.h"
#include "irq.h"
#include "console.h"
#include "stdio.h"
#include "paging.h"
#include "system/syscall.h"

#define ISR_STUB(i) extern void isr##i(void);
#define XISR(n) ISR_STUB(n)
#define REPEAT32(X) \
     X(0)  X(1)  X(2)  X(3)  X(4)  X(5)  X(6)  X(7) \
     X(8)  X(9)  X(10) X(11) X(12) X(13) X(14) X(15)\
     X(16) X(17) X(18) X(19) X(20) X(21) X(22) X(23)\
     X(24) X(25) X(26) X(27) X(28) X(29) X(30) X(31) 

REPEAT32(XISR)

#define XPTR(n) isr##n,
void *isr_stubs[32] =
{
    REPEAT32(XPTR)
};
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
    "Coprocessor Segment Overrun", // 9 (reserved/legacy)
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
    "Reserved",                    // 22
    "Reserved",                    // 23
    "Reserved",                    // 24
    "Reserved",                    // 25
    "Reserved",                    // 26
    "Reserved",                    // 27
    "Reserved",                    // 28
    "Reserved",                    // 29
    "Reserved",                    // 30
    "Reserved"                     // 31
};

void idt_init()
{
    for (int i = 0; i < 32; i++)
    {
        idt_set_entry(i, (uint32_t)isr_stubs[i], 0x08, 0x8E);
    }

    struct IDTDescriptor idt_desc;
    idt_desc.limit = sizeof(idt) - 1;
    idt_desc.base  = (uint32_t)&idt;

    asm volatile("cli");
    asm volatile("lidt %0" : : "m"(idt_desc));

    system_call_init();
}

void idt_set_entry(int num, uint32_t handler_addr, uint16_t selector, uint8_t type_attr)
{
    idt[num].offset_low  = (handler_addr & 0xFFFF);
    idt[num].selector    = selector;
    idt[num].zero        = 0;
    idt[num].type_attr   = type_attr;  // 0x8E = present, ring0, 32-bit interrupt gate
    idt[num].offset_high = (handler_addr >> 16) & 0xFFFF;
}

/* === Säkrare page-fault-utskrift, med reentransvakt och säkra hexdumps === */

static volatile int s_in_pf = 0;  // reentrans-vakt

static void print_page_fault(struct stack_frame *f)
{
    uint32_t cr2;
    asm volatile("mov %%cr2, %0" : "=r"(cr2));

    // Reentransskydd: om vi PF:ar inuti PF-handlern, skriv minimalt och stanna
    s_in_pf++;
    if (s_in_pf > 1) {
        puts("\n==== PAGE FAULT (re-entrant) ====\n");
        printf("EIP=%08x  CR2=%08x\n", f->eip, cr2);
        puts("[PF] Re-entrancy detected; skipping memory dumps.\n");
        for (;;)
            asm volatile("hlt");
    }

    printf("\n==== PAGE FAULT ====\n");
    printf("EIP=%08x  CR2=%08x\n", f->eip, cr2);
    dump_err_bits(f->err_code);

    // Regdump
    printf("EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n", f->eax, f->ebx, f->ecx, f->edx);
    printf("ESI=%08x EDI=%08x EBP=%08x ESP=%08x\n", f->esi, f->edi, f->ebp, f->esp);

    // PDE/PTE för faultande adress
    dump_pde_pte(cr2);

    // Instruktionsbytes vid EIP (kolla att den verkligen är mappad för att undvika PF i handlern)
    if (page_present(f->eip)) {
        printf("[bytes @EIP]");
        hexdump_bytes((const void*)f->eip, 16);
    } else {
        printf("[bytes @EIP] (unmapped)\n");
    }

    // Bytes vid CR2 om sidan finns
    if (page_present(cr2)) {
        printf("[bytes @CR2]");
        hexdump_bytes((const void*)cr2, 16);
    } else {
        printf("[bytes @CR2] (unmapped)\n");
    }

    // Liten stack-dump (endast om den aktuella stack-sidan är mappad)
    if (page_present(f->esp)) {
        printf("[stack]");
        hexdump_bytes((const void*)f->esp, 32);
    }

    // Stanna här så loggen hinner läsas
    for (;;)
        asm volatile("hlt");
}

void fault_handler(struct stack_frame *frame)
{
    if (frame->int_no < 32)
    {
        if (frame->int_no == 14)  // #PF
        {
            print_page_fault(frame);
        }
        for (;;)
            asm volatile("hlt");
    }
}

void dump_idt()
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

