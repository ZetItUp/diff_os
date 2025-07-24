#include "idt.h"
#include "console.h"

/*#define ISR_STUB(i) extern void isr##i(void);
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
*/


extern void isr0(void);
extern void isr1(void);
extern void isr2(void);
extern void isr3(void);
extern void isr4(void);
extern void isr5(void);
extern void isr6(void);
extern void isr7(void);
extern void isr8(void);
extern void isr9(void);
extern void isr10(void);
extern void isr11(void);
extern void isr12(void);
extern void isr13(void);
extern void isr14(void);
extern void isr15(void);
extern void isr16(void);
extern void isr17(void);
extern void isr18(void);
extern void isr19(void);
extern void isr20(void);
extern void isr21(void);
extern void isr22(void);
extern void isr23(void);
extern void isr24(void);
extern void isr25(void);
extern void isr26(void);
extern void isr27(void);
extern void isr28(void);
extern void isr29(void);
extern void isr30(void);
extern void isr31(void);


void *isr_stubs[32] = {
    isr0,  isr1,  isr2,  isr3,
    isr4,  isr5,  isr6,  isr7,
    isr8,  isr9,  isr10, isr11,
    isr12, isr13, isr14, isr15,
    isr16, isr17, isr18, isr19,
    isr20, isr21, isr22, isr23,
    isr24, isr25, isr26, isr27,
    isr28, isr29, isr30, isr31
};

unsigned char *exception_messages[] =
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
    for (int i = 0; i < IDT_SIZE; i++) 
    {
        idt[i].offset_low  = 0;
        idt[i].selector    = 0;
        idt[i].zero        = 0;
        idt[i].type_attr   = 0;
        idt[i].offset_high = 0;
    }

    for(int i = 0; i < 32; i++)
    {
        idt_set_entry(i, (uint32_t)isr_stubs[i], 0x08, 0x8E);
    }

    struct IDTDescriptor idt_desc;
    idt_desc.limit = sizeof(idt) - 1;
    idt_desc.base = (uint32_t)&idt;

for (int i = 0; i < 32; ++i) {
    puthex((uint32_t)isr_stubs[i]);
    puts(" ");
}


    while(1);
    // Load IDT with lidt
    asm volatile("lidt %0" : : "m"(idt_desc));
    asm volatile("sti");
}

void idt_set_entry(int num, uint32_t handler_addr, uint16_t selector, uint8_t type_attr)
{
    // Set lowest 16 bits of the handler address
    idt[num].offset_low = handler_addr & 0xFFFF;
    // Segment selector, usually 0x08 (Kernel code segment in GDT)
    idt[num].selector = selector;
    // Reserved,set to 0
    idt[num].zero = 0;
    // Type and attribute, (ex. 0x8E,  Present, Ring 0, 32-bit Interrupt Gate)
    idt[num].type_attr = type_attr;
    // Set highest 16 bit of the handler address
    idt[num].offset_high = (handler_addr >> 16) & 0xFFFF;
}

void fault_handler(struct err_stack_frame *frame)
{
    if(frame->int_no < 32)
    {
        set_color(MAKE_COLOR(FG_YELLOW, BG_RED));
        puts("ERROR! ");
        set_color(MAKE_COLOR(FG_WHITE, BG_RED));
        puts(exception_messages[frame->int_no]);
        set_color(MAKE_COLOR(FG_YELLOW, BG_RED));
        puts(" Exception");

        for(;;);
    }    
}
