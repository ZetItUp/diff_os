// All comments are written in English.
// Allman brace style is used consistently.

#include "system/scheduler.h"
#include "system/threads.h"
#include "heap.h"
#include "string.h"

// State

static thread_t* g_current = NULL;
static thread_t* g_run_head = NULL;
static thread_t* g_run_tail = NULL;
static thread_t* g_zombie_head = NULL;
static thread_t* g_idle = NULL;

// Internal

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

static void runq_enqueue(thread_t* thread)
{
    thread->next = NULL;
    if (!g_run_head)
    {
        g_run_head = g_run_tail = thread;
        return;
    }
    g_run_tail->next = thread;
    g_run_tail = thread;
}

static thread_t* runq_pick_next(void)
{
    thread_t* t = g_run_head;
    if (t)
    {
        g_run_head = t->next;
        if (!g_run_head) { g_run_tail = NULL; }
        t->next = NULL;
    }
    return t;
}

static thread_t* runq_detach_head(void)
{
    return runq_pick_next();
}

static void reap_zombies(void)
{
    while (g_zombie_head)
    {
        thread_t* z = g_zombie_head;
        g_zombie_head = z->next;
        if (z->kernel_stack_base) { kfree((void*)(uintptr_t)z->kernel_stack_base); }
        kfree(z);
    }
}

extern void thread_entry_thunk(void);
extern void context_switch(cpu_context_t* save_context, cpu_context_t* load_context);

static void idle_entry(void* arg)
{
    (void)arg;
    for (;;)
    {
        __asm__ __volatile__("sti; hlt");
        thread_yield();
    }
}

// API

void scheduler_init(void)
{
    uint32_t f = irq_save();

    g_current = NULL;
    g_run_head = g_run_tail = NULL;
    g_zombie_head = NULL;
    g_idle = NULL;

    // Create idle thread, then keep it out of the run queue
    thread_create(idle_entry, NULL, 16384);
    g_idle = runq_detach_head();

    irq_restore(f);
}

void scheduler_add_thread(thread_t* thread)
{
    uint32_t f = irq_save();
    thread->state = THREAD_RUNNABLE;
    runq_enqueue(thread);
    irq_restore(f);
}

thread_t* current_thread(void)
{
    return g_current;
}

void scheduler_start(void)
{
    uint32_t f = irq_save();

    static thread_t bootstrap;
    memset(&bootstrap, 0, sizeof(bootstrap));
    bootstrap.thread_id = 0;
    bootstrap.state = THREAD_RUNNING;
    g_current = &bootstrap;

    reap_zombies();

    thread_t* next = runq_pick_next();
    if (!next) { next = g_idle; }

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    thread_t* prev = g_current;
    g_current = next;

    context_switch(&prev->context, &next->context);

    irq_restore(f);

    for (;;)
    {
        __asm__ __volatile__("hlt");
    }
}

void thread_yield(void)
{
    uint32_t f = irq_save();

    reap_zombies();

    thread_t* self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    self->state = THREAD_RUNNABLE;
    runq_enqueue(self);

    thread_t* next = runq_pick_next();
    if (!next) { next = g_idle; }

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    g_current = next;

    context_switch(&self->context, &next->context);
    irq_restore(f);
}

void scheduler_block_current_until_wakeup(void)
{
    uint32_t f = irq_save();

    reap_zombies();

    thread_t* self = g_current;
    if (!self)
    {
        irq_restore(f);
        return;
    }

    self->state = THREAD_SLEEPING;

    thread_t* next = runq_pick_next();
    if (!next) { next = g_idle; }

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    g_current = next;

    context_switch(&self->context, &next->context);
    irq_restore(f);
}

void scheduler_wake_owner(void* owner)
{
    uint32_t f = irq_save();

    thread_t* t = (thread_t*)owner;
    if (t && t->state == THREAD_SLEEPING)
    {
        t->state = THREAD_RUNNABLE;
        runq_enqueue(t);
    }

    irq_restore(f);
}

void thread_exit(void)
{
    uint32_t f = irq_save();

    thread_t* self = g_current;
    self->state = THREAD_ZOMBIE;
    self->next = g_zombie_head;
    g_zombie_head = self;

    thread_t* next = runq_pick_next();
    if (!next) { next = g_idle; }

    if (next->context.eip == 0)
    {
        next->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;
    }

    next->state = THREAD_RUNNING;
    g_current = next;

    context_switch(&self->context, &next->context);

    for (;;)
    {
        __asm__ __volatile__("hlt");
    }
}

// Timer hooks

void sched_block_current_until_wakeup(void)
{
    scheduler_block_current_until_wakeup();
}

void sched_wake_owner(void* owner)
{
    scheduler_wake_owner(owner);
}

