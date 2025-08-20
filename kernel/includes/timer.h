// All comments are written in English.
// Allman brace style is used consistently.

#pragma once

#include "stdint.h"
#include <stdbool.h>

/* --------------------------------------------------------------------------
   Low-level PIT init / install (kept for backward compatibility)
   -------------------------------------------------------------------------- */

/* Initialize PIT to the given frequency (Hz). */
void timer_init(uint32_t frequency);

/* Program PIT and hook IRQ0 handler. */
void timer_install(void);

/* Legacy globals (still provided by implementation for compatibility). */
extern volatile bool timer_tick_updated;
extern volatile uint32_t timer_ticks;

/* --------------------------------------------------------------------------
   Public timebase
   -------------------------------------------------------------------------- */

/* Returns the PIT frequency (Hz) used by the subsystem. */
uint32_t timer_hz(void);

/* Monotonic ticks since boot (increments once per PIT interrupt). */
uint64_t timer_now_ticks(void);

/* Monotonic milliseconds since boot (derived from ticks/hz). */
uint64_t timer_now_ms(void);

/* --------------------------------------------------------------------------
   Timer objects
   -------------------------------------------------------------------------- */

typedef struct ktimer ktimer_t;

/* Timer callback type. Runs in IRQ context: keep it short/non-blocking. */
typedef void (*ktimer_callback_t)(void *arg);

/* Per-timer state */
struct ktimer
{
    /* Expiration time in ms (monotonic since boot). */
    uint64_t expires_ms;

    /* Period (ms). 0 => one-shot, >0 => periodic. */
    uint32_t period_ms;

    /* Callback and argument. */
    ktimer_callback_t cb;
    void *callback_arg;

    /* Optional owner pointer (process/thread etc.). */
    void *owner;

    /* Internal linkage for the timer queue. */
    struct ktimer *next;

    /* Active flag (true if armed and in the queue). */
    bool active;
};

/* Arm a one-shot timer that fires after delay_ms from now. */
void ktimer_add_once(ktimer_t *t, uint32_t delay_ms, ktimer_callback_t cb, void *arg, void *owner);

/* Arm or re-arm a periodic timer that fires every period_ms. */
void ktimer_add_periodic(ktimer_t *t, uint32_t period_ms, ktimer_callback_t cb, void *arg, void *owner);

/* Cancel a previously armed timer (safe from IRQ or thread context). */
void ktimer_cancel(ktimer_t *t);

/* --------------------------------------------------------------------------
   Sleeping
   -------------------------------------------------------------------------- */

/* Sleep for N milliseconds. With a scheduler, this will block the caller;
   without one, it falls back to a short busy-wait internally. */
void sleep_ms(uint32_t ms);

/* ----------------------------------------------------------------------
   Internal (IRQ0 tick) – called from the PIT IRQ handler.
   You normally never call this yourself.
   -------------------------------------------------------------------------- */
void ktimer_tick_isr(void);

