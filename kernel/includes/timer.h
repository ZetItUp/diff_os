#pragma once

#include "stdint.h"
#include <stdbool.h>

// Initialize the PIT to the given frequency in Hz (interrupts per second)
void timer_init(uint32_t frequency);

// Install timer IRQ handler
void timer_install(void);

extern volatile bool timer_tick_updated;
extern volatile uint32_t timer_ticks;
