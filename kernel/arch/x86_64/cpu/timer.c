#include "system/scheduler.h"
#include "system/threads.h"
#include "timer.h"
#include "irq.h"
#include "pic.h"
#include "io.h"
#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"

#define PIT_CH0_PORT 0x40
#define PIT_CMD_PORT 0x43
#define PIT_INPUT_HZ 1193182u
#define PIT_IRQ_LINE 0

#ifndef TIMER_DEFAULT_HZ
#define TIMER_DEFAULT_HZ 100u
#endif

extern thread_t* current_thread(void);
volatile uint32_t timer_ticks = 0;
volatile bool timer_tick_updated = false;

static inline uint32_t irq_save(void)
{
    uint32_t flags;

    __asm__ __volatile__("pushf; pop %0; cli" : "=r"(flags) :: "memory");  // Save EFLAGS and disabling interrupts

    return flags;
}

static inline void irq_restore(uint32_t flags)
{
    __asm__ __volatile__("push %0; popf" :: "r"(flags) : "memory");  // Restore previous EFLAGS
}

static volatile uint64_t g_ticks = 0;
static volatile uint32_t g_hz = TIMER_DEFAULT_HZ;
static volatile uint64_t g_ms = 0;
static volatile uint32_t g_ms_inc = 0;
static volatile uint32_t g_ms_rem = 0;
static volatile uint32_t g_ms_frac_accum = 0;

uint32_t timer_hz(void)
{
    return g_hz;
}

uint64_t timer_now_ticks(void)
{
    uint32_t f = irq_save();
    uint64_t t = g_ticks;

    irq_restore(f);

    return t;
}

uint64_t timer_now_ms(void)
{
    uint32_t f = irq_save();
    uint64_t ms = g_ms;

    irq_restore(f);

    return ms;
}

static struct ktimer *g_timer_head = NULL;

static void timerq_insert(struct ktimer *t)
{
    t->active = true;

    if (g_timer_head == NULL || t->expires_ms < g_timer_head->expires_ms)
    {
        t->next = g_timer_head;
        g_timer_head = t;

        return;
    }

    struct ktimer *cur = g_timer_head;

    while (cur->next && cur->next->expires_ms <= t->expires_ms)
    {
        cur = cur->next;
    }

    t->next = cur->next;
    cur->next = t;
}

static void timerq_remove(struct ktimer *t)
{
    if (!t->active)
    {
        return;
    }

    struct ktimer **pp = &g_timer_head;

    while (*pp)
    {
        if (*pp == t)
        {
            *pp = t->next;
            t->next = NULL;
            t->active = false;

            return;
        }

        pp = &((*pp)->next);
    }

    t->next = NULL;
    t->active = false;
}

void ktimer_add_once(
    struct ktimer *t,
    uint32_t delay_ms,
    ktimer_callback_t cb,
    void *arg,
    void *owner)
{
    if (!t || !cb)
    {
        return;
    }

    uint32_t f = irq_save();

    t->cb = cb;
    t->callback_arg = arg;
    t->owner = owner;
    t->period_ms = 0;
    t->expires_ms = timer_now_ms() + (uint64_t)delay_ms;
    t->next = NULL;
    t->active = false;

    timerq_insert(t);

    irq_restore(f);
}

void ktimer_add_periodic(
    struct ktimer *t,
    uint32_t period_ms,
    ktimer_callback_t cb,
    void *arg,
    void *owner)
{
    if (!t || !cb || period_ms == 0)
    {
        return;
    }

    uint32_t f = irq_save();

    t->cb = cb;
    t->callback_arg = arg;
    t->owner = owner;
    t->period_ms = period_ms;
    t->expires_ms = timer_now_ms() + (uint64_t)period_ms;
    t->next = NULL;
    t->active = false;

    timerq_insert(t);

    irq_restore(f);
}

void ktimer_cancel(struct ktimer *t)
{
    if (!t)
    {
        return;
    }

    uint32_t f = irq_save();

    timerq_remove(t);

    irq_restore(f);
}

__attribute__((weak)) void scheduler_block_current_until_wakeup(void) 
{ 

} 

__attribute__((weak)) void schededuler_wake_owner(void *owner) 
{ 
    (void)owner; 
} 

typedef struct sleep_helper
{
    struct ktimer timer;
    volatile bool woke;
    void *owner;
} sleep_helper_t;

static void sleep_cb(void *arg)
{
    sleep_helper_t *h = (sleep_helper_t *)arg;
    h->woke = true;

    if (h->owner)
    {
        scheduler_wake_owner(h->owner);  
    }
}

void sleep_ms(uint32_t ms)
{
    void *owner = current_thread(); 

    sleep_helper_t helper;
    helper.woke = false;
    helper.owner = owner;

    ktimer_add_once(&helper.timer, ms, sleep_cb, &helper, owner);

    scheduler_block_current_until_wakeup();  

    while (!helper.woke)
    {
        __asm__ __volatile__("pause");
    }
}

static void pit_program(uint32_t hz)
{
    if (hz < 19)
    {
        hz = 19;  // This needs to be >= ~19 Hz to avoid divisor underflow
    }

    uint32_t divisor = PIT_INPUT_HZ / hz;

    if (divisor == 0)
    {
        divisor = 1;  // This needs to be >=1 for PIT programming
    }

    outb(PIT_CMD_PORT, 0x36);  // Programming PIT ch0, lobyte/hibyte, mode 3 (square wave)

    outb(PIT_CH0_PORT, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0_PORT, (uint8_t)((divisor >> 8) & 0xFF));

    uint32_t f = irq_save();

    g_hz = hz;
    g_ms_inc = 1000u / hz; 
    g_ms_rem = 1000u % hz;
    g_ms_frac_accum = 0; 

    irq_restore(f);
}

void ktimer_tick_isr(void)
{
    extern void keyboard_drain(void);

    g_ticks++;
    timer_ticks++;
    timer_tick_updated = true;

    uint32_t hz = g_hz;
    g_ms += g_ms_inc;  // Advancing monotonic ms by integer part

    uint32_t acc = g_ms_frac_accum + g_ms_rem;  // Accumulating fractional ms for correction

    if (acc >= hz)
    {
        g_ms += 1;     // Calculating the time correction by carrying 1 ms
        acc -= hz;     // Attempting to preserve leftover fractional part
    }

    g_ms_frac_accum = acc;

    // Drain keyboard scan codes from driver and process them
    // This triggers keyboard_process_scancode → push_key_event → writes to TTY
    keyboard_drain();

    uint64_t now_ms = g_ms;  // Reading current ms for timer expirations

    while (g_timer_head && g_timer_head->expires_ms <= now_ms)
    {
        struct ktimer *t = g_timer_head;
        g_timer_head = t->next;
        t->next = NULL;
        t->active = false;

        if (t->period_ms != 0)
        {
            t->expires_ms = now_ms + (uint64_t)t->period_ms;  // Attempting to re-arm periodic timer to reduce drift
            timerq_insert(t);
        }

        if (t->cb)
        {
            t->cb(t->callback_arg);  // This needs to be fast (IRQ context)
        }
    }
}

static void timer_irq_handler(unsigned irq, void *ctx)
{
    (void)irq;
    (void)ctx;

    ktimer_tick_isr();
    scheduler_tick_from_timer();
}

void timer_init(uint32_t frequency)
{
    pit_program(frequency);  // Attempting to program PIT to requested frequency
}

void timer_install(void)
{
    pit_program(TIMER_DEFAULT_HZ);  // Start with default frequency

    irq_install_handler(PIT_IRQ_LINE, timer_irq_handler);  // This needs to be bound to IRQ0
    pic_clear_mask(PIT_IRQ_LINE);  // This needs to unmask IRQ0 on PIC
}
