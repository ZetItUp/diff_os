#include "timer.h"
#include "stddef.h"
#include "io.h"
#include "irq.h"

#define TIMER_CHANNEL0        0x40
#define TIMER_COMMAND         0x43
#define TIMER_IRQ              0

// Global tick count
volatile uint32_t timer_ticks = 0;

// Timer Handler
static void timer_handler(uint32_t irq, void *context)
{
    (void)irq;
    (void)context;      // Unused
                        
    //timer_ticks++;
}

/*
 * Initialize the Programmable Interrupt Timer to a desired frequency (Hz)
 * The PIT clock is set to 1193182 Hz
 */
void timer_init(uint32_t frequency)
{
    uint32_t divisor = 1193182 / frequency;

    // Send command byte: channel 0, low+high byte, mode 3 (square wave), binary
    outb(TIMER_COMMAND, 0x36);
    // Send frequency divisor (low byte, then high byte)
    outb(TIMER_CHANNEL0, (uint8_t)(divisor & 0xFF));
    outb(TIMER_CHANNEL0, (uint8_t)((divisor >> 8) & 0xFF));
}

// Set up the timer, Initialize the PIT and install IRQ0 handler
void timer_install(void)
{
    timer_init(100);    // 100 Hz (10 ms tick)
    irq_install_handler(TIMER_IRQ, timer_handler);
}
