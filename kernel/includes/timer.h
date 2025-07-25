#pragma once

#include "stdint.h"

// Initialize the PIT to the given frequency in Hz (interrupts per second)
void timer_init(uint32_t frequency);

// Install timer IRQ handler
void timer_install(void);
