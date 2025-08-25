#include "system/scheduler.h"
#include "system/threads.h"
#include "system/process.h"
#include "system/tss.h"
#include "heap.h"
#include "string.h"
#include "paging.h"
#include "stdio.h"
#include "diff.h"

static thread_t *g_current = NULL;         // Current running thread
static thread_t *g_run_queue_head = NULL;  // Run queue head
static thread_t *g_run_queue_tail = NULL;  // Run queue tail
static thread_t *g_zombie_head = NULL;     // Zombie list head
static thread_t *g_idle = NULL;            // Idle thread

#ifdef DIFF_DEBUG
#  define SDBG(...) printf(__VA_ARGS__)
#else
#  define SDBG(...) do {} while (0)
#endif

// Assembly thunks
extern void thread_entry_thunk(void);
extern void context_switch(cpu_context_t *save, cpu_context_t *load);

// Notify waiter when a process becomes zombie
static void process_notify_exit(process_t *p)
{
    if (p && p->waiter)
    {
        scheduler_wake_owner(p->waiter);
    }
}

// Switch to next thread's address space if owner differs
static inline void switch_address_space_if_needed(thread_t *next)
{
    process_t *np = next ? next->owner_process : NULL;

    if (np && np != process_current())
    {
        paging_switch_address_space(np->cr3);
        process_set_current(np);
    }
}


// Save flags and disable interrupts
static inline uint32_t irq_save(void)
{
    uint32_t flags;
    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

// Restore interrupt flags
static inline void irq_restore(uint32_t flags)
{
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory");
}

// Return top of kernel stack for TSS
static inline uint32_t thread_kstack_top(const thread_t *t)
{
    return t ? t->kernel_stack_top : 0;
}

// Enqueue at tail
static void run_queue_enqueue(thread_t *t)
{
    // Idle must never enter the queue
    if (t == g_idle)
    {
        return;
    }

    // New tail will have no next
    t->next = NULL;

    // Empty queue becomes single element
    if (!g_run_queue_head)
    {
        g_run_queue_head = t;
        g_run_queue_tail = t;
        SDBG("[SCH] enqueue: tid=%d (head)\n", t->thread_id);
        return;
    }

    // Append to tail
    g_run_queue_tail->next = t;
    g_run_queue_tail = t;
    SDBG("[SCH] enqueue: tid=%d\n", t->thread_id);
}

// Enqueue at head
static void run_queue_enqueue_front(thread_t *t)
{
    // Never queue idle
    if (t == g_idle)
    {
        return;
    }

    // If empty, make into a single element
    if (!g_run_queue_head)
    {
        t->next = NULL;
        g_run_queue_head = t;
        g_run_queue_tail = t;
        SDBG("[SCH] enqueue(front): tid=%d (head)\n", t->thread_id);
        return;
    }

    // Link in front
    t->next = g_run_queue_head;
    g_run_queue_head = t;
    SDBG("[SCH] enqueue(front): tid=%d\n", t->thread_id);
}

// Pop head from run queue
static thread_t *run_queue_pick_next(void)
{
    thread_t *t = g_run_queue_head;

    // Detach head if present
    if (t)
    {
        g_run_queue_head = t->next;

        // If list is empty, clear tail
        if (!g_run_queue_head)
        {
            g_run_queue_tail = NULL;
        }

        t->next = NULL;
    }

    SDBG("[SCH] pick_next -> %s\n", t ? "thread" : "idle/null");
    return t;
}

// Detach and return head
static thread_t *run_queue_detach_head(void)
{
    return run_queue_pick_next();
}

// Mark thread as zombie and update owner process
static void scheduler_mark_zombie(thread_t *t)
{
    if (!t || t->state == THREAD_ZOMBIE)
    {
        return;
    }

    SDBG("[SCH] mark_zombie: tid=%d pid=%d\n",
         t->thread_id, t->owner_process ? t->owner_process->pid : -1);

    t->state = THREAD_ZOMBIE;

    // Push to zombie list head
    t->next = g_zombie_head;
    g_zombie_head = t;

    if (t->owner_process)
    {
        process_t *p = t->owner_process;

        // Decrement live thread count if positive
        if (p->live_threads > 0)
        {
            p->live_threads--;
        }

        // Mark process as zombie when last thread is gone
        if (p->pid != 0 && p->live_threads == 0 && p->state != PROCESS_ZOMBIE)
        {
            p->state = PROCESS_ZOMBIE;
            SDBG("[SCH] process -> ZOMBIE: pid=%d\n", p->pid);
            process_notify_exit(p);
        }
    }
}

// Free all zombie threads, process objects are reaped elsewhere
static void reap_zombies(void)
{
    while (g_zombie_head)
    {
        thread_t *z = g_zombie_head;
        g_zombie_head = z->next;

        SDBG("[SCH] reap thread: tid=%d pid=%d\n",
             z->thread_id, z->owner_process ? z->owner_process->pid : -1);

        // Free kernel stack if present
        if (z->kernel_stack_base)
        {
            kfree((void *)(uintptr_t)z->kernel_stack_base);
        }

        // Free thread object
        kfree(z);
    }
}

// Pick next runnable thread, skip threads whose process is zombie
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

        // Skip threads owned by a zombie process
        if (next != g_idle && p && p->state == PROCESS_ZOMBIE)
        {
            scheduler_mark_zombie(next);
            continue;
        }

        return next;
    }
}

// Idle loop, enables interrupts, halts, then yields
static void idle_entry(void *arg)
{
    (void)arg;

    for (;;)
    {
        __asm__ __volatile__("sti; hlt");
        thread_yield();
    }
}

// Return the current running thread
thread_t *current_thread(void)
{
    return g_current;
}

// Add a thread to the scheduler run queue
void scheduler_add_thread(thread_t *t)
{
    uint32_t f = irq_save();

    // Skip if owner process is already zombie
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

// Initialize scheduler and create idle thread
void scheduler_init(void)
{
    uint32_t f = irq_save();

    g_current = NULL;
    g_run_queue_head = g_run_queue_tail = NULL;
    g_zombie_head = NULL;
    g_idle = NULL;

    // Create the idle thread and immediately detach it from the queue
    thread_create(idle_entry, NULL, 16384);
    g_idle = run_queue_detach_head();

    // Initialize TSS with idle thread's kernel stack
    tss_init(thread_kstack_top(g_idle));

    SDBG("[SCH] init: idle tid=%d pid=%d\n",
         g_idle ? g_idle->thread_id : -1,
         (g_idle && g_idle->owner_process) ? g_idle->owner_process->pid : -1);

    irq_restore(f);
}

// Start scheduling, switch from bootstrap thread to first runnable thread
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

    // If thread has no entry, set entry thunk
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    // Load CR3 and update TSS for next thread
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

// Yield the CPU to the next runnable thread
void thread_yield(void)
{
    uint32_t f = irq_save();

    // Reap finished threads before picking next
    reap_zombies();

    thread_t *self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    // If we were running, move us back to runnable
    if (self != g_idle && self->state == THREAD_RUNNING)
    {
        self->state = THREAD_READY;
    }

    // Put current thread at queue tail if it is runnable
    if (self != g_idle && self->state == THREAD_READY)
    {
        run_queue_enqueue(self);
    }

    // Pick next runnable or idle
    thread_t *next = pick_next_alive();

    // Install entry thunk if needed
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    // Load address space and kernel stack for next
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

// Block current thread until someone wakes it
void scheduler_block_current_until_wakeup(void)
{
    uint32_t f = irq_save();

    // Reap finished threads before blocking
    reap_zombies();

    thread_t *self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    // Go to sleeping state
    self->state = THREAD_SLEEPING;

    // Pick next runnable or idle
    thread_t *next = pick_next_alive();

    // Install entry thunk if needed
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    // Load address space and kernel stack for next
    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    SDBG("[SCH] block: tid=%d -> next tid=%d (pid=%d)\n",
         self->thread_id,
         next->thread_id,
         next->owner_process ? next->owner_process->pid : -1);

    g_current = next;
    context_switch(&self->context, &next->context);

    // We resume here after being woken
    SDBG("[SCH] resume: tid=%d pid=%d\n",
         self->thread_id, self->owner_process ? self->owner_process->pid : -1);

    irq_restore(f);
}

// Wake a specific sleeping thread by owner pointer
void scheduler_wake_owner(void *owner)
{
    uint32_t f = irq_save();

    thread_t *t = (thread_t *)owner;
    if (t)
    {
        // If the owner process is zombie, mark thread zombie
        if (t->owner_process && t->owner_process->state == PROCESS_ZOMBIE)
        {
            SDBG("[SCH] wake_owner: tid=%d owner pid=%d is ZOMBIE\n",
                 t->thread_id, t->owner_process->pid);
            scheduler_mark_zombie(t);
        }
        else if (t->state == THREAD_SLEEPING)
        {
            // Make runnable and favor it by enqueueing at head
            t->state = THREAD_READY;
            run_queue_enqueue_front(t);
            SDBG("[SCH] wake_owner: tid=%d enqueued (front)\n", t->thread_id);
        }
        else
        {
            // Not sleeping, ignore
            SDBG("[SCH] wake_owner: tid=%d state=%d (ignored)\n", t->thread_id, t->state);
        }
    }

    irq_restore(f);
}

// Terminate the current thread and switch away
void thread_exit(void)
{
    uint32_t f = irq_save();
    (void)f;

    thread_t *self = g_current;

    SDBG("[SCH] thread_exit: tid=%d pid=%d\n",
         self ? self->thread_id : -1,
         (self && self->owner_process) ? self->owner_process->pid : -1);

    // Move current to zombie list and update owning process
    scheduler_mark_zombie(self);

    // Pick next runnable or idle
    thread_t *next = pick_next_alive();

    // Install entry thunk if needed
    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;

    // Load address space and kernel stack for next
    switch_address_space_if_needed(next);
    tss_set_esp0(thread_kstack_top(next));

    g_current = next;
    context_switch(&self->context, &next->context);

    // Should never return
    for (;;)
    {
    }
}

