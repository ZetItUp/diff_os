#include "system/scheduler.h"
#include "system/threads.h"
#include "system/process.h"
#include "system/tss.h"
#include "heap.h"
#include "string.h"
#include "paging.h"
#include "stdio.h"
#include "diff.h"

/* Scheduler — stable multi-exec
 *
 * Key points:
 *  - Switch CR3 when changing process (switch_address_space_if_needed).
 *  - Update TSS.esp0 on every switch (correct kernel stack).
 *  - Only reap THREADS here; a PROCESS is reaped by wait() in process layer.
 *  - Wake parent when last thread dies and process becomes ZOMBIE.
 *  - Idle thread never goes into the run queue.
 */

static thread_t *g_current         = NULL;
static thread_t *g_run_queue_head  = NULL;
static thread_t *g_run_queue_tail  = NULL;
static thread_t *g_zombie_head     = NULL;
static thread_t *g_idle            = NULL;

#ifdef DIFF_DEBUG
#  define SDBG(...) printf(__VA_ARGS__)
#else
#  define SDBG(...) do {} while (0)
#endif

/* -------------------------------------------------------------------------- */
/* IRQ helpers                                                                */
/* -------------------------------------------------------------------------- */
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

/* -------------------------------------------------------------------------- */
/* Run-queue helpers                                                          */
/* -------------------------------------------------------------------------- */
static inline uint32_t thread_kstack_top(const thread_t *t)
{
    return t ? t->kernel_stack_top : 0;
}

/* Enqueue at tail */
static void run_queue_enqueue(thread_t *t)
{
    if (t == g_idle)
    {
        return; /* idle must never enter the queue */
    }

    t->next = NULL;

    if (!g_run_queue_head)
    {
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue: tid=%d (head)\n", t->thread_id);

        return;
    }

    g_run_queue_tail->next = t;
    g_run_queue_tail = t;
    SDBG("[SCH] enqueue: tid=%d\n", t->thread_id);
}

/* Enqueue at head (prioritize woken threads) */
static void run_queue_enqueue_front(thread_t *t)
{
    if (t == g_idle)
    {
        return;
    }

    if (!g_run_queue_head)
    {
        t->next = NULL;
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue(front): tid=%d (head)\n", t->thread_id);

        return;
    }

    t->next = g_run_queue_head;
    g_run_queue_head = t;
    SDBG("[SCH] enqueue(front): tid=%d\n", t->thread_id);
}

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

    SDBG("[SCH] pick_next -> %s\n", t ? "thread" : "idle/null");

    return t;
}

static thread_t *run_queue_detach_head(void)
{
    return run_queue_pick_next();
}

/* -------------------------------------------------------------------------- */
/* Process/exit notification                                                  */
/* -------------------------------------------------------------------------- */
static void process_notify_exit(process_t *p)
{
    if (p && p->waiter)
    {
        scheduler_wake_owner(p->waiter);
        /* The waiter clears p->waiter when it resumes from block. */
    }
}

/* Switch address space if the next thread belongs to another process. */
static inline void switch_address_space_if_needed(thread_t *next)
{
    process_t *np = next ? next->owner_process : NULL;

    if (np && np != process_current())
    {
        paging_switch_address_space(np->cr3);
        process_set_current(np);
    }
}

/* -------------------------------------------------------------------------- */
/* Zombie handling (only reaps THREADS here)                                   */
/* -------------------------------------------------------------------------- */
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

static void reap_zombies(void)
{
    while (g_zombie_head)
    {
        thread_t *z = g_zombie_head;
        g_zombie_head = z->next;

        SDBG("[SCH] reap thread: tid=%d pid=%d\n",
             z->thread_id, z->owner_process ? z->owner_process->pid : -1);

        /* Free ONLY the thread resources here. */
        if (z->kernel_stack_base)
        {
            kfree((void *)(uintptr_t)z->kernel_stack_base);
        }

        kfree(z);
        /* Process object is reaped by process_wait(). */
    }
}

/* -------------------------------------------------------------------------- */
/* Next thread selection (skip threads whose owner is already ZOMBIE)         */
/* -------------------------------------------------------------------------- */
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
            continue; /* skip and try next */
        }

        return next;
    }
}

/* -------------------------------------------------------------------------- */
/* Context-switch glue                                                        */
/* -------------------------------------------------------------------------- */
extern void thread_entry_thunk(void);
extern void context_switch(cpu_context_t *save_context, cpu_context_t *load_context);

/* -------------------------------------------------------------------------- */
/* Idle                                                                       */
/* -------------------------------------------------------------------------- */
static void idle_entry(void *arg)
{
    (void)arg;

    for (;;)
    {
        __asm__ __volatile__("sti; hlt");
        thread_yield();
    }
}

/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */
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

    t->state = THREAD_RUNNABLE;

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

    /* Create the idle thread and immediately detach it from the queue. */
    thread_create(idle_entry, NULL, 16384);
    g_idle = run_queue_detach_head();

    /* Initialize TSS with idle's kernel stack (updated on every switch). */
    tss_init(thread_kstack_top(g_idle));

    SDBG("[SCH] init: idle tid=%d pid=%d\n",
         g_idle ? g_idle->thread_id : -1,
         (g_idle && g_idle->owner_process) ? g_idle->owner_process->pid : -1);

    irq_restore(f);
}

void scheduler_start(void)
{
    uint32_t f = irq_save();

    static thread_t bootstrap;

    memset(&bootstrap, 0, sizeof(bootstrap));
    bootstrap.thread_id = 0;
    bootstrap.state     = THREAD_RUNNING;
    g_current = &bootstrap;

    SDBG("[SCH] start\n");

    thread_t *next = pick_next_alive();

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    /* CR3 + TSS to the next thread */
    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

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

    reap_zombies();

    thread_t *self = g_current;
    if (!self)
    {
        irq_restore(f);

        return;
    }

    if (self != g_idle && self->state == THREAD_RUNNING)
    {
        self->state = THREAD_RUNNABLE;
    }

    if (self != g_idle && self->state == THREAD_RUNNABLE)
    {
        run_queue_enqueue(self);
    }

    thread_t *next = pick_next_alive();

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    SDBG("[SCH] yield: %d -> %d (pid=%d)\n",
         self->thread_id,
         next->thread_id,
         next->owner_process ? next->owner_process->pid : -1);

    g_current = next;
    context_switch(&self->context, &next->context);

    irq_restore(f);
}

void scheduler_block_current_until_wakeup(void)
{
    uint32_t f = irq_save();

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

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    SDBG("[SCH] block: tid=%d -> next tid=%d (pid=%d)\n",
         self->thread_id,
         next->thread_id,
         next->owner_process ? next->owner_process->pid : -1);

    g_current = next;
    context_switch(&self->context, &next->context);

    /* When we resume here, self has been woken. */
    SDBG("[SCH] resume: tid=%d pid=%d\n",
         self->thread_id, self->owner_process ? self->owner_process->pid : -1);

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
            SDBG("[SCH] wake_owner: tid=%d owner pid=%d is ZOMBIE\n",
                 t->thread_id, t->owner_process->pid);
            scheduler_mark_zombie(t);
        }
        else if (t->state == THREAD_SLEEPING)
        {
            t->state = THREAD_RUNNABLE;
            run_queue_enqueue_front(t);
            SDBG("[SCH] wake_owner: tid=%d enqueued (front)\n", t->thread_id);
        }
        else
        {
            SDBG("[SCH] wake_owner: tid=%d state=%d (ignored)\n", t->thread_id, t->state);
        }
    }

    irq_restore(f);
}

void thread_exit(void)
{
    uint32_t f = irq_save();
    (void)f;

    thread_t *self = g_current;

    SDBG("[SCH] thread_exit: tid=%d pid=%d\n",
         self ? self->thread_id : -1,
         (self && self->owner_process) ? self->owner_process->pid : -1);

    scheduler_mark_zombie(self);

    thread_t *next = pick_next_alive();

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    g_current = next;
    context_switch(&self->context, &next->context);
}

