#include "system/scheduler.h"
#include "system/threads.h"
#include "timer.h"
#include "irq.h"
#include "pic.h"
#include "io.h"
#include "stdint.h"
#include "stddef.h"
#include "stdbool.h"

/* --------------------------------------------------------------------------
   PIT hardware
   -------------------------------------------------------------------------- */

#define PIT_CH0_PORT   0x40
#define PIT_CMD_PORT   0x43
#define PIT_INPUT_HZ   1193182u
#define PIT_IRQ_LINE   0

#ifndef TIMER_DEFAULT_HZ
#define TIMER_DEFAULT_HZ 100u      /* 100 Hz = 10 ms tick */
#endif

/* --------------------------------------------------------------------------
   Legacy globals (kept for compatibility with existing code)
   -------------------------------------------------------------------------- */
extern thread_t* current_thread(void);
volatile uint32_t timer_ticks = 0;
volatile bool     timer_tick_updated = false;

/* Save/restore IF helpers (avoid enabling interrupts accidentally) */
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

/* --------------------------------------------------------------------------
   Global timebase (no 64-bit division)
   -------------------------------------------------------------------------- */

static volatile uint64_t g_ticks = 0;   /* increments once per PIT IRQ */
static volatile uint32_t g_hz    = TIMER_DEFAULT_HZ;

/* Millisecond accumulator:
   Every tick we add:
     g_ms += ms_inc;
     frac_accum += ms_rem;
     if (frac_accum >= hz) { g_ms++; frac_accum -= hz; }
   where ms_inc = 1000 / hz, ms_rem = 1000 % hz.
*/
static volatile uint64_t g_ms = 0;          /* monotonic milliseconds since boot */
static volatile uint32_t g_ms_inc = 0;      /* floor(1000 / hz) */
static volatile uint32_t g_ms_rem = 0;      /* (1000 % hz) */
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
    uint64_t ms = g_ms;              /* already maintained tick-by-tick */
    irq_restore(f);
    return ms;
}

/* --------------------------------------------------------------------------
   Timer queue (earliest-expiring first)
   -------------------------------------------------------------------------- */

static struct ktimer *g_timer_head = NULL;

/* Queue helpers (caller holds irq_save/irq_restore) */
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

/* --------------------------------------------------------------------------
   Public timer API
   -------------------------------------------------------------------------- */

void ktimer_add_once(struct ktimer *t, uint32_t delay_ms, ktimer_callback_t cb, void *arg, void *owner)
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

void ktimer_add_periodic(struct ktimer *t, uint32_t period_ms, ktimer_callback_t cb, void *arg, void *owner)
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

/* --------------------------------------------------------------------------
   Sleep support (busy-wait fallback; will block with a scheduler later)
   -------------------------------------------------------------------------- */

__attribute__((weak)) void sched_block_current_until_wakeup(void) { /* weak stub */ }
__attribute__((weak)) void sched_wake_owner(void *owner) { (void)owner; /* weak stub */ }

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
        sched_wake_owner(h->owner);
    }
}

void sleep_ms(uint32_t ms)
{
    void *owner = current_thread();

    sleep_helper_t helper;
    helper.woke = false;
    helper.owner = owner;

    ktimer_add_once(&helper.timer, ms, sleep_cb, &helper, owner);

    sched_block_current_until_wakeup();

    while (!helper.woke)
    {
        __asm__ __volatile__("pause");
    }
}

/* --------------------------------------------------------------------------
   PIT programming and IRQ path
   -------------------------------------------------------------------------- */

static void pit_program(uint32_t hz)
{
    /* Guard against nonsense values; also avoid divisor=0 */
    if (hz < 19)
    {
        hz = 19; /* ~52.6 ms/tick worst case */
    }

    uint32_t divisor = PIT_INPUT_HZ / hz;
    if (divisor == 0)
    {
        divisor = 1;
    }

    /* Command: ch0, access mode lobyte/hibyte, mode 3 (square wave), binary */
    outb(PIT_CMD_PORT, 0x36);

    /* Divisor low, then high */
    outb(PIT_CH0_PORT, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0_PORT, (uint8_t)((divisor >> 8) & 0xFF));

    /* Update globals and ms accumulator parameters atomically */
    uint32_t f = irq_save();
    g_hz = hz;
    g_ms_inc = 1000u / hz;  /* integer part */
    g_ms_rem = 1000u % hz;  /* fractional remainder */
    g_ms_frac_accum = 0;    /* reset frac accumulator on reprogramming */
    irq_restore(f);
}

/* Called by IRQ0 handler */
void ktimer_tick_isr(void)
{
    /* Bump tick counters */
    g_ticks++;
    timer_ticks++;
    timer_tick_updated = true;

    /* Advance monotonic milliseconds without division */
    uint32_t hz = g_hz;  /* read once */
    g_ms += g_ms_inc;
    uint32_t acc = g_ms_frac_accum + g_ms_rem;
    if (acc >= hz)
    {
        g_ms += 1;
        acc -= hz;
    }
    g_ms_frac_accum = acc;

    /* Expire any timers that are due (loop to handle multiple) */
    uint64_t now_ms = g_ms; /* already atomic enough inside IRQ */
    while (g_timer_head && g_timer_head->expires_ms <= now_ms)
    {
        struct ktimer *t = g_timer_head;
        g_timer_head = t->next;
        t->next = NULL;
        t->active = false;

        /* Periodic: re-arm before callback to reduce drift */
        if (t->period_ms != 0)
        {
            t->expires_ms = now_ms + (uint64_t)t->period_ms;
            timerq_insert(t);
        }

        if (t->cb)
        {
            t->cb(t->callback_arg); /* Runs in IRQ context: keep it quick */
        }
    }
}

static void timer_irq_handler(unsigned irq, void *ctx)
{
    (void)irq;
    (void)ctx;
    ktimer_tick_isr();
}

/* --------------------------------------------------------------------------
   Public init
   -------------------------------------------------------------------------- */

void timer_init(uint32_t frequency)
{
    pit_program(frequency);
}

void timer_install(void)
{
    /* Program PIT at default HZ and hook IRQ0 */
    pit_program(TIMER_DEFAULT_HZ);

    /* Register IRQ0 handler and unmask the line */
    irq_install_handler(PIT_IRQ_LINE, timer_irq_handler);
    pic_clear_mask(PIT_IRQ_LINE);
}

