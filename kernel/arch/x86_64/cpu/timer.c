#include "system/scheduler.h"
#include "system/threads.h"
#include "timer.h"
#include "irq.h"
#include "pic.h"
#include "apic.h"
#include "io.h"
#include <stdio.h>
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

extern thread_t *current_thread(void);
volatile uint32_t timer_ticks = 0;
volatile bool timer_tick_updated = false;

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

static volatile uint64_t g_tick_count = 0;
static volatile uint32_t g_timer_hertz = TIMER_DEFAULT_HZ;
static volatile uint64_t g_milliseconds = 0;
static volatile uint32_t g_millisecond_increment = 0;
static volatile uint32_t g_millisecond_remainder = 0;
static volatile uint32_t g_millisecond_fraction_accum = 0;

uint32_t timer_hz(void)
{
    return g_timer_hertz;
}

uint64_t timer_now_ticks(void)
{
    uint32_t irq_flags = irq_save();
    uint64_t tick_count = g_tick_count;

    irq_restore(irq_flags);

    return tick_count;
}

uint64_t timer_now_ms(void)
{
    uint32_t irq_flags = irq_save();
    uint64_t milliseconds = g_milliseconds;

    irq_restore(irq_flags);

    return milliseconds;
}

static struct ktimer *g_timer_head = NULL;

static void timerq_insert(struct ktimer *timer)
{
    timer->active = true;

    if (g_timer_head == NULL || timer->expires_ms < g_timer_head->expires_ms)
    {
        timer->next = g_timer_head;
        g_timer_head = timer;

        return;
    }

    struct ktimer *current_timer = g_timer_head;

    while (current_timer->next &&
           current_timer->next->expires_ms <= timer->expires_ms)
    {
        current_timer = current_timer->next;
    }

    timer->next = current_timer->next;
    current_timer->next = timer;
}

static void timerq_remove(struct ktimer *timer)
{
    if (!timer->active)
    {
        return;
    }

    struct ktimer **timer_ptr = &g_timer_head;

    while (*timer_ptr)
    {
        if (*timer_ptr == timer)
        {
            *timer_ptr = timer->next;
            timer->next = NULL;
            timer->active = false;

            return;
        }

        timer_ptr = &((*timer_ptr)->next);
    }

    timer->next = NULL;
    timer->active = false;
}

void ktimer_add_once(
    struct ktimer *timer,
    uint32_t delay_ms,
    ktimer_callback_t callback,
    void *callback_arg,
    void *owner)
{
    if (!timer || !callback)
    {
        return;
    }

    uint32_t irq_flags = irq_save();

    timer->cb = callback;
    timer->callback_arg = callback_arg;
    timer->owner = owner;
    timer->period_ms = 0;
    timer->expires_ms = timer_now_ms() + (uint64_t)delay_ms;
    timer->next = NULL;
    timer->active = false;

    timerq_insert(timer);

    irq_restore(irq_flags);
}

void ktimer_add_periodic(
    struct ktimer *timer,
    uint32_t period_ms,
    ktimer_callback_t callback,
    void *callback_arg,
    void *owner)
{
    if (!timer || !callback || period_ms == 0)
    {
        return;
    }

    uint32_t irq_flags = irq_save();

    timer->cb = callback;
    timer->callback_arg = callback_arg;
    timer->owner = owner;
    timer->period_ms = period_ms;
    timer->expires_ms = timer_now_ms() + (uint64_t)period_ms;
    timer->next = NULL;
    timer->active = false;

    timerq_insert(timer);

    irq_restore(irq_flags);
}

void ktimer_cancel(struct ktimer *timer)
{
    if (!timer)
    {
        return;
    }

    uint32_t irq_flags = irq_save();

    timerq_remove(timer);

    irq_restore(irq_flags);
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

static void sleep_cb(void *argument)
{
    sleep_helper_t *helper = (sleep_helper_t *)argument;
    helper->woke = true;

    if (helper->owner)
    {
        scheduler_wake_owner(helper->owner);
    }
}

void sleep_ms(uint32_t milliseconds)
{
    void *owner = current_thread();

    sleep_helper_t helper;
    helper.woke = false;
    helper.owner = owner;

    ktimer_add_once(&helper.timer, milliseconds, sleep_cb, &helper, owner);

    scheduler_block_current_until_wakeup();

    while (!helper.woke)
    {
        __asm__ __volatile__("pause");
    }
}

static void pit_program(uint32_t frequency_hertz)
{
    if (frequency_hertz < 19)
    {
        frequency_hertz = 19;
    }

    uint32_t divisor = PIT_INPUT_HZ / frequency_hertz;

    if (divisor == 0)
    {
        divisor = 1;
    }

    outb(PIT_CMD_PORT, 0x36);

    outb(PIT_CH0_PORT, (uint8_t)(divisor & 0xFF));
    outb(PIT_CH0_PORT, (uint8_t)((divisor >> 8) & 0xFF));

    uint32_t irq_flags = irq_save();

    g_timer_hertz = frequency_hertz;
    g_millisecond_increment = 1000u / frequency_hertz;
    g_millisecond_remainder = 1000u % frequency_hertz;
    g_millisecond_fraction_accum = 0;

    irq_restore(irq_flags);
}

void ktimer_tick_isr(void)
{
    extern void keyboard_drain(void);

    g_tick_count++;
    timer_ticks++;
    timer_tick_updated = true;

    uint32_t current_hertz = g_timer_hertz;
    g_milliseconds += g_millisecond_increment;

    uint32_t fraction_accum =
        g_millisecond_fraction_accum + g_millisecond_remainder;

    if (fraction_accum >= current_hertz)
    {
        g_milliseconds += 1;
        fraction_accum -= current_hertz;
    }

    g_millisecond_fraction_accum = fraction_accum;


    // Drain keyboard scan codes and process them
    keyboard_drain();

    uint64_t now_milliseconds = g_milliseconds;

    while (g_timer_head && g_timer_head->expires_ms <= now_milliseconds)
    {
        struct ktimer *timer = g_timer_head;
        g_timer_head = timer->next;
        timer->next = NULL;
        timer->active = false;

        if (timer->period_ms != 0)
        {
            timer->expires_ms = now_milliseconds + (uint64_t)timer->period_ms;
            timerq_insert(timer);
        }

        if (timer->cb)
        {
            timer->cb(timer->callback_arg);
        }
    }
}

static void timer_irq_handler(unsigned irq_number, void *context)
{
    (void)irq_number;
    (void)context;

    ktimer_tick_isr();
    scheduler_tick_from_timer();
}

void timer_init(uint32_t frequency)
{
    pit_program(frequency);
}

void timer_install(void)
{
    pit_program(TIMER_DEFAULT_HZ);

    irq_install_handler(PIT_IRQ_LINE, timer_irq_handler);
    pic_clear_mask(PIT_IRQ_LINE);
}

void timer_install_apic(void)
{
    // Install timer handler for APIC timer
    irq_install_handler(PIT_IRQ_LINE, timer_irq_handler);

    // Set up the timer frequency tracking values for APIC timer
    uint32_t irq_flags = irq_save();
    g_timer_hertz = TIMER_DEFAULT_HZ;
    g_millisecond_increment = 1000u / g_timer_hertz;
    g_millisecond_remainder = 1000u % g_timer_hertz;
    g_millisecond_fraction_accum = 0;
    irq_restore(irq_flags);
}
