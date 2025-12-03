#pragma once

#include "stdint.h"
#include <stdbool.h>

// Keep old globals so legacy code still compiles
extern volatile bool timer_tick_updated;
extern volatile uint32_t timer_ticks;

void timer_init(uint32_t frequency);
void timer_install(void);
void timer_install_apic(void);

uint32_t timer_hz(void);
uint64_t timer_now_ticks(void);
uint64_t timer_now_ms(void);

typedef struct ktimer ktimer_t;

typedef void (*ktimer_callback_t)(void *arg);

struct ktimer
{
    uint64_t expires_ms;
    uint32_t period_ms;
    ktimer_callback_t cb;
    void *callback_arg;
    void *owner;
    struct ktimer *next;
    bool active;
};

// Runs once after delay_ms
void ktimer_add_once(ktimer_t *t, uint32_t delay_ms, ktimer_callback_t cb, void *arg, void *owner);

// Keeps firing every period_ms
void ktimer_add_periodic(ktimer_t *t, uint32_t period_ms, ktimer_callback_t cb, void *arg, void *owner);

// Turn off a timer that’s active
void ktimer_cancel(ktimer_t *t);

// With scheduler this blocks, otherwise it busy-waits
void sleep_ms(uint32_t ms);

// Called every PIT tick to update timers
void ktimer_tick_isr(void);

