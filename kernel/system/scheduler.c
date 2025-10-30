// scheduler.c

#include "system/scheduler.h"
#include "system/threads.h"
#include "system/process.h"
#include "system/tss.h"
#include "system/gdt.h"
#include "heap.h"
#include "string.h"
#include "paging.h"
#include "stdio.h"
#include "diff.h"

#ifdef DIFF_DEBUG
#   define SDBG(...) printf(__VA_ARGS__)
#else
#   define SDBG(...) do {} while (0)
#endif

// Assembly thunks
extern void thread_entry_thunk(void);
extern void context_switch(cpu_context_t *save, cpu_context_t *load);

// -----------------------------------------------------------------------------
// Scheduler state
// -----------------------------------------------------------------------------
static thread_t *g_current         = NULL; // current running
static thread_t *g_run_queue_head  = NULL; // ready queue head
static thread_t *g_run_queue_tail  = NULL; // ready queue tail
static thread_t *g_zombie_head     = NULL; // zombie list
static thread_t *g_idle            = NULL; // idle thread

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

static inline void fxsave(void *area16)
{
    __asm__ volatile ("fxsave (%0)" :: "r"(area16) : "memory");
}

static inline void fxrstor(const void *area16)
{
    __asm__ volatile ("fxrstor (%0)" :: "r"(area16));
}

static inline uint32_t thread_kstack_top(const thread_t *t)
{
    return t ? t->kernel_stack_top : 0;
}

static inline uint32_t irq_save(void)
{
    uint32_t flags;
    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static inline void irq_restore(uint32_t flags)
{
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory");
}

static void process_notify_exit(process_t *p)
{
    if (p && p->waiter)
    {
        scheduler_wake_owner(p->waiter);
    }
}

#ifdef DIFF_DEBUG
static void sch_dump_ctx(const char *tag, const thread_t *t)
{
    if (!t) { SDBG("[SCH][%s] <null thread>\n", tag); return; }
    const process_t *p = t->owner_process;
    SDBG("[SCH][%s] tid=%d pid=%d state=%d eip=%08x esp=%08x ebp=%08x kstack_top=%08x cr3=%08x\n",
         tag,
         t->thread_id,
         p ? p->pid : -1,
         t->state,
         t->context.eip, t->context.esp, t->context.ebp,
         t->kernel_stack_top,
         p ? p->cr3 : 0);
}

static void sch_dump_run_queue(const char *tag)
{
    SDBG("[SCH][%s] runq:", tag);
    thread_t *it = g_run_queue_head;
    if (!it) { SDBG(" <empty>\n"); return; }
    while (it)
    {
        SDBG(" [tid=%d pid=%d]", it->thread_id, it->owner_process ? it->owner_process->pid : -1);
        it = it->next;
    }
    SDBG("\n");
}
#endif

// enqueue tail (skip idle)
static void run_queue_enqueue(thread_t *t)
{
    if (!t || t == g_idle)
    {
        return;
    }

    t->next = NULL;
    if (!g_run_queue_head)
    {
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue: tid=%d (head)\n", t->thread_id);
#ifdef DIFF_DEBUG
        sch_dump_run_queue("enqueue");
#endif
        return;
    }
    g_run_queue_tail->next = t;
    g_run_queue_tail = t;
    SDBG("[SCH] enqueue: tid=%d\n", t->thread_id);
#ifdef DIFF_DEBUG
    sch_dump_run_queue("enqueue");
#endif
}

// enqueue head (skip idle)
static void run_queue_enqueue_front(thread_t *t)
{
    if (!t || t == g_idle)
    {
        return;
    }

    if (!g_run_queue_head)
    {
        t->next = NULL;
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue(front): tid=%d (head)\n", t->thread_id);
#ifdef DIFF_DEBUG
        sch_dump_run_queue("enqueue_front");
#endif
        return;
    }
    t->next = g_run_queue_head;
    g_run_queue_head = t;
    SDBG("[SCH] enqueue(front): tid=%d\n", t->thread_id);
#ifdef DIFF_DEBUG
    sch_dump_run_queue("enqueue_front");
#endif
}

// pop head
static thread_t *run_queue_pick_next(void)
{
    thread_t *t = g_run_queue_head;
    if (t)
    {
        g_run_queue_head = t->next;
        if (!g_run_queue_head)
        {
            g_run_queue_tail = NULL;
        }
        t->next = NULL;
    }
    if (t)
    {
        SDBG("[SCH] pick_next -> thread\n");
    }
    else
    {
        SDBG("[SCH] pick_next -> idle/null\n");
    }
#ifdef DIFF_DEBUG
    sch_dump_run_queue("pick_next.after");
#endif
    return t;
}

// Byt adressrymd om nästa tråds ägare skiljer sig från "current"
static inline void switch_address_space_if_needed(thread_t *next)
{
    if (!next)
    {
        return;
    }

    process_t *curp = process_current();
    process_t *np   = next->owner_process;

    if (!np || np == curp)
    {
        return;
    }

    uint32_t have = read_cr3_local();
    if (have != np->cr3)
    {
        SDBG("[SCH] CR3 switch: %08x -> %08x (to pid=%d)\n", have, np->cr3, np->pid);
        paging_switch_address_space(np->cr3);
#ifdef DIFF_DEBUG
        uint32_t now = read_cr3_local();
        if (now != np->cr3)
        {
            SDBG("[SCH][WARN] CR3 after switch != expected: now=%08x expected=%08x\n", now, np->cr3);
        }
#endif
    }
    process_set_current(np);
}

// Mark thread as zombie
static void scheduler_mark_zombie(thread_t *t)
{
    if (!t || t->state == THREAD_ZOMBIE)
    {
        return;
    }

    SDBG("[SCH] mark_zombie: tid=%d pid=%d\n",
         t->thread_id, t->owner_process ? t->owner_process->pid : -1);

    t->state = THREAD_ZOMBIE;
    t->next  = g_zombie_head;
    g_zombie_head = t;

    if (t->owner_process)
    {
        process_t *p = t->owner_process;
        if (p->live_threads > 0)
        {
            p->live_threads--;
        }

        if (p->pid != 0 && p->live_threads == 0 && p->state != PROCESS_ZOMBIE)
        {
            p->state = PROCESS_ZOMBIE;
            SDBG("[SCH] process -> ZOMBIE: pid=%d\n", p->pid);
            process_notify_exit(p);
        }
    }
}

// Reap zombie threads
static void reap_zombies(void)
{
#ifdef DIFF_DEBUG
    if (!g_zombie_head) { return; }
#endif
    while (g_zombie_head)
    {
        thread_t *z = g_zombie_head;
        g_zombie_head = z->next;
        z->next = NULL;

        SDBG("[SCH] reap thread: tid=%d\n", z->thread_id);
        threads_reap_one(z);
    }
}

// Reap all zombies owned by a given process
void scheduler_reap_owned_zombies(process_t *p)
{
    if (!p)
    {
        return;
    }

    thread_t *prev = NULL, *it = g_zombie_head;
    while (it)
    {
        thread_t *nxt = it->next;
        if (it->owner_process == p)
        {
            if (prev) prev->next = nxt;
            else      g_zombie_head = nxt;

            it->next = NULL;
            SDBG("[SCH] reap thread: tid=%d pid=%d\n", it->thread_id, p->pid);
            threads_reap_one(it);
            it = nxt;
            continue;
        }
        prev = it;
        it = nxt;
    }
}

// Pick next alive
static thread_t *pick_next_alive(void)
{
    for (;;)
    {
        thread_t *next = run_queue_pick_next();
        if (!next)
        {
            return g_idle;
        }

        process_t *p = next->owner_process;
        if (next != g_idle && p && p->state == PROCESS_ZOMBIE)
        {
            scheduler_mark_zombie(next);
            continue;
        }
        return next;
    }
}

// Idle loop
static void idle_entry(void *arg)
{
    (void)arg;
#ifdef DIFF_DEBUG
    SDBG("[SCH] idle_entry started (tid=%d)\n", current_thread() ? current_thread()->thread_id : -1);
#endif
    for (;;)
    {
        __asm__ __volatile__("sti; hlt");
        thread_yield();
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

thread_t *current_thread(void)
{
    return g_current;
}

void scheduler_add_thread(thread_t *t)
{
    uint32_t f = irq_save();

    if (t->owner_process && t->owner_process->state == PROCESS_ZOMBIE)
    {
        SDBG("[SCH] add_thread: owner pid=%d is ZOMBIE, tid=%d -> zombie\n",
             t->owner_process->pid, t->thread_id);
        scheduler_mark_zombie(t);
        irq_restore(f);
        return;
    }

    t->state = THREAD_READY;
    SDBG("[SCH] add_thread: tid=%d pid=%d\n",
         t->thread_id, t->owner_process ? t->owner_process->pid : -1);
    run_queue_enqueue(t);

    irq_restore(f);
}

void scheduler_init(void)
{
    uint32_t f = irq_save();

    g_current = NULL;
    g_run_queue_head = g_run_queue_tail = NULL;
    g_zombie_head = NULL;
    g_idle = NULL;

    // 1) Init GDT först
    gdt_init();

    // 2) Skriv in en giltig TSS-deskriptor i den GDT som just laddades
    tss_install_in_gdt((void*)gdt_get_base(), GDT_TSS_SEL);

    // 3) Skapa idle-tråd (behövs för esp0)
    thread_create(idle_entry, NULL, 16384);
    g_idle = run_queue_pick_next();

    // 4) Initiera TSS med idle-trådens kernelstack och ladda TR
    tss_init(thread_kstack_top(g_idle));

    irq_restore(f);

    SDBG("[SCH] init: idle tid=%d pid=%d\n",
         g_idle ? g_idle->thread_id : -1,
         (g_idle && g_idle->owner_process) ? g_idle->owner_process->pid : -1);
#ifdef DIFF_DEBUG
    sch_dump_ctx("init.idle", g_idle);
#endif
}

void scheduler_start(void)
{
    uint32_t f = irq_save();

    static thread_t bootstrap;
    memset(&bootstrap, 0, sizeof(bootstrap));
    bootstrap.thread_id = 0;
    bootstrap.state = THREAD_RUNNING;
    g_current = &bootstrap;

    SDBG("[SCH] start\n");

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

#ifdef DIFF_DEBUG
    sch_dump_ctx("start.next", next);
#endif

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

#ifdef DIFF_DEBUG
    SDBG("[SCH] tss.esp0 <= %08x\n", thread_kstack_top(next));
#endif

    if (next->fx_area_aligned)
    {
        if (!next->fx_valid)
        {
            __asm__ __volatile__("fninit");
            fxsave(next->fx_area_aligned);
            next->fx_valid = true;
        }
        fxrstor(next->fx_area_aligned);
    }

    SDBG("[SCH] switch -> tid=%d pid=%d eip=%08x esp=%08x\n",
         next->thread_id,
         next->owner_process ? next->owner_process->pid : -1,
         next->context.eip, next->context.esp);

    g_current = next;
    context_switch(&bootstrap.context, &next->context);

    irq_restore(f);
}

void thread_yield(void)
{
    uint32_t f = irq_save();

#ifdef DIFF_DEBUG
    sch_dump_ctx("yield.self", g_current);
#endif

    reap_zombies();

    thread_t *self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    if (self != g_idle && self->state == THREAD_RUNNING)
    {
        self->state = THREAD_READY;
    }

    if (self != g_idle && self->state == THREAD_READY)
    {
        run_queue_enqueue(self);
    }

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

#ifdef DIFF_DEBUG
    sch_dump_ctx("yield.next", next);
#endif

    if (self->fx_area_aligned)
    {
        fxsave(self->fx_area_aligned);
        self->fx_valid = true;
    }

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));
#ifdef DIFF_DEBUG
    SDBG("[SCH] tss.esp0 <= %08x\n", thread_kstack_top(next));
#endif

    if (next->fx_area_aligned)
    {
        if (!next->fx_valid)
        {
            __asm__ __volatile__("fninit");
            fxsave(next->fx_area_aligned);
            next->fx_valid = true;
        }
        fxrstor(next->fx_area_aligned);
    }

    g_current = next;
    context_switch(&self->context, &next->context);

    irq_restore(f);
}

void scheduler_block_current_until_wakeup(void)
{
    uint32_t f = irq_save();

#ifdef DIFF_DEBUG
    sch_dump_ctx("block.self", g_current);
#endif

    reap_zombies();

    thread_t *self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    self->state = THREAD_SLEEPING;

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

#ifdef DIFF_DEBUG
    sch_dump_ctx("block.next", next);
#endif

    if (self->fx_area_aligned)
    {
        fxsave(self->fx_area_aligned);
        self->fx_valid = true;
    }

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));
#ifdef DIFF_DEBUG
    SDBG("[SCH] tss.esp0 <= %08x\n", thread_kstack_top(next));
#endif

    if (next->fx_area_aligned)
    {
        if (!next->fx_valid)
        {
            __asm__ __volatile__("fninit");
            fxsave(next->fx_area_aligned);
            next->fx_valid = true;
        }
        fxrstor(next->fx_area_aligned);
    }

    g_current = next;
    context_switch(&self->context, &next->context);

    process_t *p = self->owner_process;
    if (p)
    {
        uint32_t cur = read_cr3_local();
        if (cur != p->cr3)
        {
            paging_switch_address_space(p->cr3);
#ifdef DIFF_DEBUG
            SDBG("[SCH] restore CR3 to owner pid=%d: %08x\n", p->pid, p->cr3);
#endif
        }
        tss_set_esp0(thread_kstack_top(self));
#ifdef DIFF_DEBUG
        SDBG("[SCH] restore tss.esp0 <= %08x (self)\n", thread_kstack_top(self));
#endif
    }

    irq_restore(f);
}

void scheduler_wake_owner(void *owner)
{
    uint32_t f = irq_save();

    thread_t *t = (thread_t *)owner;
    if (t)
    {
        if (t->owner_process && t->owner_process->state == PROCESS_ZOMBIE)
        {
            scheduler_mark_zombie(t);
        }
        else if (t->state == THREAD_SLEEPING)
        {
            t->state = THREAD_READY;
            run_queue_enqueue_front(t);
            SDBG("[SCH] wake: tid=%d pid=%d\n",
                 t->thread_id, t->owner_process ? t->owner_process->pid : -1);
        }
    }

    irq_restore(f);
}

void thread_exit(void)
{
    uint32_t f = irq_save();

#ifdef DIFF_DEBUG
    sch_dump_ctx("exit.self", g_current);
#endif

    thread_t *self = g_current;
    scheduler_mark_zombie(self);

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

#ifdef DIFF_DEBUG
    sch_dump_ctx("exit.next", next);
#endif

    if (self && self->fx_area_aligned)
    {
        fxsave(self->fx_area_aligned);
        self->fx_valid = true;
    }

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));
#ifdef DIFF_DEBUG
    SDBG("[SCH] tss.esp0 <= %08x\n", thread_kstack_top(next));
#endif

    if (next->fx_area_aligned)
    {
        if (!next->fx_valid)
        {
            __asm__ __volatile__("fninit");
            fxsave(next->fx_area_aligned);
            next->fx_valid = true;
        }
        fxrstor(next->fx_area_aligned);
    }

    g_current = next;
    context_switch(&self->context, &next->context);

    for (;;)
    {
    }
}

