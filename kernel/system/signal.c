#include "system/signal.h"
#include "system/process.h"
#include "system/syscall.h"
#include "system/scheduler.h"
#include "system/usercopy.h"
#include "paging.h"
#include "stdio.h"
#include "system.h"

typedef struct user_signal_frame
{
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;

    uint32_t gs;
    uint32_t fs;
    uint32_t es;
    uint32_t ds;

    uint32_t eip;
    uint32_t cs;
    uint32_t eflags;
    uint32_t useresp;
    uint32_t ss;

    uint32_t sigmask;
} user_signal_frame_t;

static int signal_valid(int sig)
{
    return sig > 0 && sig < SIG_MAX;
}

static int signal_next_pending(const signal_state_t *s)
{
    uint32_t pending = s->pending & ~s->mask;
    if (!pending)
    {
        return 0;
    }
    return (int)__builtin_ctz(pending);
}

int signal_send_to_process(process_t *p, int sig)
{
    if (!p || !signal_valid(sig))
    {
        return -1;
    }

    p->sig.pending |= (1u << sig);
    if (p->main_thread)
    {
        scheduler_wake_owner(p->main_thread);
    }
    return 0;
}

int system_signal_send(int pid, int sig)
{
    if (!signal_valid(sig))
    {
        return -1;
    }

    process_t *p = NULL;
    if (pid == 0)
    {
        p = process_current();
    }
    else
    {
        p = process_find_by_pid(pid);
    }

    if (!p)
    {
        return -1;
    }

    return signal_send_to_process(p, sig);
}

int system_signal_set(int sig, user_sighandler_t handler, uint32_t trampoline)
{
    if (!signal_valid(sig))
    {
        return -1;
    }

    process_t *p = process_current();
    if (!p)
    {
        return -1;
    }

    if (handler != SIG_DFL && handler != SIG_IGN)
    {
        if (trampoline == 0)
        {
            return -1;
        }
        if (!p->sig.trampoline)
        {
            p->sig.trampoline = trampoline;
        }
    }

    p->sig.handlers[sig] = handler;
    return 0;
}

int system_signal_setmask(uint32_t mask)
{
    process_t *p = process_current();
    if (!p)
    {
        return -1;
    }

    p->sig.mask = mask & ~1u;
    return 0;
}

int system_signal_getmask(uint32_t *out)
{
    process_t *p = process_current();
    if (!p || !out)
    {
        return -1;
    }

    return copy_to_user(out, &p->sig.mask, sizeof(p->sig.mask));
}

static int signal_frame_write(uint32_t sp, uint32_t sig, uint32_t trampoline,
                              const user_signal_frame_t *frame)
{
    uint32_t frame_addr = sp - (uint32_t)sizeof(*frame);
    uint32_t sig_addr = frame_addr - sizeof(uint32_t);
    uint32_t ret_addr = sig_addr - sizeof(uint32_t);
    uint32_t total = (uint32_t)sizeof(*frame) + 8;

    if (paging_check_user_range(ret_addr, total) != 0)
    {
        return -1;
    }

    if (copy_to_user((void *)(uintptr_t)frame_addr, frame, sizeof(*frame)) != 0)
    {
        return -1;
    }

    if (copy_to_user((void *)(uintptr_t)sig_addr, &sig, sizeof(sig)) != 0)
    {
        return -1;
    }

    if (copy_to_user((void *)(uintptr_t)ret_addr, &trampoline, sizeof(trampoline)) != 0)
    {
        return -1;
    }

    return (int)ret_addr;
}

static int signal_deliver_to_syscall(process_t *p, struct syscall_frame *f, int sig)
{
    user_signal_frame_t sf = {0};
    sf.edi = f->edi;
    sf.esi = f->esi;
    sf.ebp = f->ebp;
    sf.esp = f->esp;
    sf.ebx = f->ebx;
    sf.edx = f->edx;
    sf.ecx = f->ecx;
    sf.eax = f->eax;
    sf.gs = f->gs;
    sf.fs = f->fs;
    sf.es = f->es;
    sf.ds = f->ds;
    sf.eip = f->eip;
    sf.cs = f->cs;
    sf.eflags = f->eflags;
    sf.useresp = f->useresp;
    sf.ss = f->ss;
    sf.sigmask = p->sig.mask;

    int ret_addr = signal_frame_write(f->useresp, (uint32_t)sig, p->sig.trampoline, &sf);
    if (ret_addr < 0)
    {
        return -1;
    }

    f->useresp = (uint32_t)ret_addr;
    f->eip = (uint32_t)(uintptr_t)p->sig.handlers[sig];
    return 0;
}

static int signal_deliver_to_frame(process_t *p, struct stack_frame *f, int sig)
{
    user_signal_frame_t sf = {0};
    sf.edi = f->edi;
    sf.esi = f->esi;
    sf.ebp = f->ebp;
    sf.esp = f->esp;
    sf.ebx = f->ebx;
    sf.edx = f->edx;
    sf.ecx = f->ecx;
    sf.eax = f->eax;
    sf.gs = f->gs;
    sf.fs = f->fs;
    sf.es = f->es;
    sf.ds = f->ds;
    sf.eip = f->eip;
    sf.cs = f->cs;
    sf.eflags = f->eflags;
    sf.useresp = f->useresp;
    sf.ss = f->ss;
    sf.sigmask = p->sig.mask;

    int ret_addr = signal_frame_write(f->useresp, (uint32_t)sig, p->sig.trampoline, &sf);
    if (ret_addr < 0)
    {
        return -1;
    }

    f->useresp = (uint32_t)ret_addr;
    f->eip = (uint32_t)(uintptr_t)p->sig.handlers[sig];
    return 0;
}

static int signal_handle(process_t *p, int sig)
{
    if (!p || !signal_valid(sig))
    {
        return -1;
    }

    user_sighandler_t handler = p->sig.handlers[sig];
    if (handler == SIG_IGN)
    {
        p->sig.pending &= ~(1u << sig);
        return 1;
    }

    if (handler == SIG_DFL || handler == NULL)
    {
        printf("[SIGNAL] Process %d killed by signal %d (default handler)\n",
               p ? p->pid : -1, sig);
        process_exit_current(128 + sig);
    }

    return 0;
}

void signal_maybe_deliver_syscall(process_t *p, struct syscall_frame *f)
{
    if (!p || !f)
    {
        return;
    }

    if ((f->cs & 3u) != 3u)
    {
        return;
    }

    int sig = signal_next_pending(&p->sig);
    if (!signal_valid(sig))
    {
        return;
    }

    if (signal_handle(p, sig) != 0)
    {
        return;
    }

    p->sig.pending &= ~(1u << sig);
    uint32_t old_mask = p->sig.mask;
    p->sig.mask = old_mask | (1u << sig);

    if (signal_deliver_to_syscall(p, f, sig) != 0)
    {
        process_exit_current(128 + sig);
    }
}

void signal_maybe_deliver_frame(process_t *p, struct stack_frame *f)
{
    if (!p || !f)
    {
        return;
    }

    if ((f->cs & 3u) != 3u)
    {
        return;
    }

    int sig = signal_next_pending(&p->sig);
    if (!signal_valid(sig))
    {
        return;
    }

    if (signal_handle(p, sig) != 0)
    {
        return;
    }

    p->sig.pending &= ~(1u << sig);
    uint32_t old_mask = p->sig.mask;
    p->sig.mask = old_mask | (1u << sig);

    if (signal_deliver_to_frame(p, f, sig) != 0)
    {
        process_exit_current(128 + sig);
    }
}

int system_signal_return(uint32_t frame_ptr, struct syscall_frame *f)
{
    if (!f || frame_ptr == 0)
    {
        return -1;
    }

    user_signal_frame_t sf;
    if (copy_from_user(&sf, (const void *)(uintptr_t)frame_ptr, sizeof(sf)) != 0)
    {
        return -1;
    }

    process_t *p = process_current();
    if (!p)
    {
        return -1;
    }

    p->sig.mask = sf.sigmask;

    f->edi = sf.edi;
    f->esi = sf.esi;
    f->ebp = sf.ebp;
    f->ebx = sf.ebx;
    f->edx = sf.edx;
    f->ecx = sf.ecx;
    f->eax = sf.eax;

    f->gs = sf.gs;
    f->fs = sf.fs;
    f->es = sf.es;
    f->ds = sf.ds;

    f->eip = sf.eip;
    f->cs = sf.cs;
    f->eflags = sf.eflags;
    f->useresp = sf.useresp;
    f->ss = sf.ss;

    return 0;
}
