#include "stdint.h"
#include "console.h"
#include "idt.h"
#include "system/syscall.h"
#include "stdio.h"

extern void system_call_stub(void);

static uint8_t s_exit_kstack[4096];

static void user_exit_trampoline(void) __attribute__((noreturn));
static void user_exit_trampoline(void)
{
    puts("[SYSTEM] Program exited successfully!\n");
    // TODO: här kan du städa upp: unmapa user image, fria RAM, visa prompt, starta nästa program, etc.
    for (;;)
        asm volatile("hlt");
}

static int system_exit(struct syscall_frame *f, int code)
{
    (void)code;
    
    f->eip = (uint32_t)user_exit_trampoline;
    f->cs = KERNEL_CS;
    f->eflags |= 0x200;
    f->useresp = (uint32_t)(s_exit_kstack + sizeof(s_exit_kstack) - 16);
    f->ss = KERNEL_DS;

    return 0;

}

static int system_putchar(int ch)
{
    putch((char)ch);

    return 0;
}

static int system_print(const char *s)
{
    puts(s);

    return 0;
}

int system_call_dispatch(struct syscall_frame *f)
{
    int num = (int)f->eax;
    int arg0 = (int)f->ebx;
    int arg1 = (int)f->ecx;
    int arg2 = (int)f->edx;
    int arg3 = (int)f->esi;

    int ret = -1;

    // Unused for now
    (void)arg1;
    (void)arg2;
    (void)arg3;

    switch(num)
    {
        case SYSTEM_EXIT:
            ret = system_exit(f, arg0);
            
            break;
        case SYSTEM_PUTCHAR:
            ret = system_putchar(arg0);
            
            break;
        case SYSTEM_PRINT:
            ret = system_print((const char *)arg0);

            break;
        default:
            puts("[System Call] Unknown number: ");
            puthex(num);
            puts("\n");
            ret = -1;
            break;
    }

    f->eax = (uint32_t)ret; // Return value to userland

    return ret;
}

void system_call_init(void)
{
    idt_set_entry(0x66, (uint32_t)system_call_stub, 0x08, 0xEE);
}
