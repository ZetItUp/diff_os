// scheduler.c

#include "system/scheduler.h"
#include "system/threads.h"
#include "system/process.h"
#include "system/tss.h"
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
static volatile int g_need_resched = 0;    // preempt flag from timer
static int g_in_resched            = 0;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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
        scheduler_wake_owner(p->waiter);
}

// enqueue tail (skip idle)
static void run_queue_enqueue(thread_t *t)
{
    if (!t || t == g_idle) return;

    t->next = NULL;
    SDBG("[SCH] enqueue: tid=%d pid=%d\n", t->thread_id, t->owner_process ? t->owner_process->pid : -1);
    if (!g_run_queue_head) {
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue: tid=%d (head)\n", t->thread_id);
        return;
    }
    g_run_queue_tail->next = t;
    g_run_queue_tail = t;
}

// enqueue head (skip idle)
static void run_queue_enqueue_front(thread_t *t)
{
    if (!t || t == g_idle) return;

    if (!g_run_queue_head) {
        t->next = NULL;
        g_run_queue_head = g_run_queue_tail = t;
        SDBG("[SCH] enqueue(front): tid=%d pid=%d (head)\n", t->thread_id, t->owner_process ? t->owner_process->pid : -1);
        return;
    }
    t->next = g_run_queue_head;
    g_run_queue_head = t;
    SDBG("[SCH] enqueue(front): tid=%d pid=%d\n", t->thread_id, t->owner_process ? t->owner_process->pid : -1);
}

// pop head
static thread_t *run_queue_pick_next(void)
{
    thread_t *t = g_run_queue_head;
    if (t) {
        g_run_queue_head = t->next;
        if (!g_run_queue_head) g_run_queue_tail = NULL;
        t->next = NULL;
    }
    if (t)  SDBG("[SCH] pick_next -> thread tid=%d pid=%d\n", t->thread_id, t->owner_process ? t->owner_process->pid : -1);
    else    SDBG("[SCH] pick_next -> idle/null\n");
    return t;
}

// Byt adressrymd om nästa tråds ägare skiljer sig från "current"
// Uppdaterar även process_current()/set_current för spårning.
static inline void switch_address_space_if_needed(thread_t *next)
{
    if (!next) return;

    process_t *curp = process_current();
    process_t *np   = next->owner_process;

    if (!np || np == curp) return;

    uint32_t have = read_cr3_local();
    if (have != np->cr3) {
        SDBG("[SCH] CR3 switch: %08x -> %08x (to pid=%d)\n", have, np->cr3, np->pid);
        paging_switch_address_space(np->cr3);
    }
    process_set_current(np);
}

static inline void set_process_state_locked(process_t *p, process_state_t state)
{
    if (!p)
    {
        return;
    }

    uint32_t pf = 0;
    spin_lock_irqsave(&p->lock, &pf);
    p->state = state;
    spin_unlock_irqrestore(&p->lock, pf);
}

// Markera tråd som zombie (säker, påverkar inte freed processfält)
static void scheduler_mark_zombie(thread_t *t)
{
    if (!t || t->state == THREAD_ZOMBIE) return;

    SDBG("[SCH] mark_zombie: tid=%d pid=%d\n",
         t->thread_id, t->owner_process ? t->owner_process->pid : -1);

    t->state = THREAD_ZOMBIE;
    t->next  = g_zombie_head;
    g_zombie_head = t;

    if (t->owner_process) {
        process_t *p = t->owner_process;
        int notify_waiter = 0;
        uint32_t pf = 0;
        spin_lock_irqsave(&p->lock, &pf);
        if (p->live_threads > 0) p->live_threads--;
        int remaining = p->live_threads;
        if (p->pid != 0 && remaining == 0 && p->state != PROCESS_ZOMBIE) {
            p->state = PROCESS_ZOMBIE;
            notify_waiter = 1;
            SDBG("[SCH] process -> ZOMBIE: pid=%d\n", p->pid);
        }
        spin_unlock_irqrestore(&p->lock, pf);

        if (notify_waiter) {
            process_notify_exit(p);
        }
    }
}

// Reapa alla zombietrådar (rör endast trådens kernelresurser)
static void reap_zombies(void)
{
    while (g_zombie_head) {
        thread_t *z = g_zombie_head;
        g_zombie_head = z->next;
        z->next = NULL;

        SDBG("[SCH] reap thread: tid=%d\n", z->thread_id);
        threads_reap_one(z);
    }
}

// Reapa alla zombietrådar som ägs av process p (för waitpid)
void scheduler_reap_owned_zombies(process_t *p)
{
    if (!p) return;

    thread_t *prev = NULL, *it = g_zombie_head;
    while (it) {
        thread_t *nxt = it->next;
        if (it->owner_process == p) {
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

// Välj nästa körbar (hoppa över trådar vars process redan är zombie)
static thread_t *pick_next_alive(void)
{
    for (;;) {
        thread_t *next = run_queue_pick_next();
        if (!next) return g_idle;

        process_t *p = next->owner_process;
        if (next != g_idle && p && p->state == PROCESS_ZOMBIE) {
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
    for (;;) {
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

    if (t->owner_process && t->owner_process->state == PROCESS_ZOMBIE) {
        SDBG("[SCH] add_thread: owner pid=%d is ZOMBIE, tid=%d -> zombie\n",
             t->owner_process->pid, t->thread_id);
        scheduler_mark_zombie(t);
        irq_restore(f);
        return;
    }

    t->state = THREAD_READY;
    set_process_state_locked(t->owner_process, PROCESS_READY);
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

    // Skapa idle-tråden och plocka ut den direkt
    thread_create(idle_entry, NULL, 16384);
    g_idle = run_queue_pick_next();

    // Initiera TSS med idle-trådens kernel-stack
    tss_init(thread_kstack_top(g_idle));

    irq_restore(f);

    SDBG("[SCH] init: idle tid=%d pid=%d\n",
         g_idle ? g_idle->thread_id : -1,
         (g_idle && g_idle->owner_process) ? g_idle->owner_process->pid : -1);
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
    if (next->context.eip == 0) {
        SDBG("[SCH] WARNING: next thread tid=%d has EIP=0, setting to thunk\n", next->thread_id);
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    set_process_state_locked(next->owner_process, PROCESS_RUNNING);
    set_process_state_locked(next->owner_process, PROCESS_RUNNING);
    set_process_state_locked(next->owner_process, PROCESS_RUNNING);

    // Ladda adressrymd + TSS
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
    if (!self) { irq_restore(f); return; }

    if (self != g_idle && self->state == THREAD_RUNNING)
    {
        self->state = THREAD_READY;
        set_process_state_locked(self->owner_process, PROCESS_READY);
    }

    if (self != g_idle && self->state == THREAD_READY)
        run_queue_enqueue(self);

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0) {
        SDBG("[SCH] WARNING: next thread tid=%d has EIP=0, setting to thunk\n", next->thread_id);
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    set_process_state_locked(next->owner_process, PROCESS_RUNNING);

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
    if (!self) { irq_restore(f); return; }

    self->state = THREAD_SLEEPING;

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0) {
        SDBG("[SCH] WARNING: next thread tid=%d has EIP=0, setting to thunk\n", next->thread_id);
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    SDBG("[SCH] block: tid=%d -> next tid=%d (pid=%d)\n",
         self->thread_id,
         next->thread_id,
         next->owner_process ? next->owner_process->pid : -1);

    // Verify pointers before context switch
    uint32_t esp_val;
    __asm__ volatile("mov %%esp, %0" : "=r"(esp_val));
    SDBG("[SCH] actual ESP=%08x, &self->context=%08x, &next->context=%08x\n",
         esp_val, (uint32_t)&self->context, (uint32_t)&next->context);

    g_current = next;
    context_switch(&self->context, &next->context);

    // --- Här återupptas 'self' efter wake_owner() ---
    // Viktigt: säkerställ att rätt CR3 är laddad för den återupptagna tråden,
    // annars kan vi få userspace EIP men fel adressrymd -> page fault.
    {
        process_t *p = self->owner_process;
        if (p) {
            uint32_t cur = read_cr3_local();
            if (cur != p->cr3) {
                SDBG("[SCH] CR3 switch (resume): %08x -> %08x (to pid=%d)\n",
                     cur, p->cr3, p->pid);
                paging_switch_address_space(p->cr3);
                process_set_current(p);
            }
            // Uppdatera TSS.esp0 inför kommande traps/syscalls
            tss_set_esp0(thread_kstack_top(self));
        }
    }

    SDBG("[SCH] resume: tid=%d pid=%d\n",
         self->thread_id, self->owner_process ? self->owner_process->pid : -1);

    irq_restore(f);
}

void scheduler_wake_owner(void *owner)
{
    uint32_t f = irq_save();

    thread_t *t = (thread_t *)owner;
    if (t) {
        if (t->owner_process && t->owner_process->state == PROCESS_ZOMBIE) {
            SDBG("[SCH] wake_owner: tid=%d owner pid=%d is ZOMBIE\n",
                 t->thread_id, t->owner_process->pid);
            scheduler_mark_zombie(t);
        } else if (t->state == THREAD_SLEEPING) {
            t->state = THREAD_READY;
            run_queue_enqueue_front(t); // väck ASAP
            SDBG("[SCH] wake_owner: tid=%d enqueued (front)\n", t->thread_id);
        } else {
            SDBG("[SCH] wake_owner: tid=%d state=%d (ignored)\n", t->thread_id, t->state);
        }
    }

    irq_restore(f);
}

void thread_exit(void)
{
    irq_save();

    thread_t *self = g_current;
    SDBG("[SCH] thread_exit: tid=%d pid=%d\n",
         self ? self->thread_id : -1,
         (self && self->owner_process) ? self->owner_process->pid : -1);

    scheduler_mark_zombie(self);

    thread_t *next = pick_next_alive();
    if (next->context.eip == 0) {
        SDBG("[SCH] WARNING: next thread tid=%d has EIP=0, setting to thunk\n", next->thread_id);
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    g_current = next;
    context_switch(&self->context, &next->context);

    for (;;)
        ; // ska aldrig återvända
}

void scheduler_tick_from_timer(void)
{
    g_need_resched = 1;
}

void scheduler_handle_irq_exit(void)
{
    if (!g_need_resched)
    {
        return;
    }
    if (g_in_resched)
    {
        return;
    }

    if (!g_run_queue_head)
    {
        g_need_resched = 0;
        return;
    }

    g_need_resched = 0;
    g_in_resched = 1;
    thread_yield();
    g_in_resched = 0;
}

void scheduler_reap_all_zombies(void)
{
    uint32_t f = irq_save();
    reap_zombies();
    irq_restore(f);
}
