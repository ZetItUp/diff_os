#pragma once

#include <stdint.h>

typedef void (*irqsw_handler_t)(void *context);

void irqsw_init(void);
int irqsw_queue(irqsw_handler_t handler, void *context);
uint32_t irqsw_dropped_count(void);
