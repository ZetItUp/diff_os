#pragma once

#include "drivers/ddf.h"

typedef struct driver
{
    const char *name;
    int irq_line;

    void (*init)(void);
    void (*handle_irq)(void);
    void (*exit)(void);
} driver_t;

#define MAX_DRIVERS 32

void driver_printf(kernel_exports_t *exports, const char *fmt, ...);
void driver_register(driver_t *drv);
void driver_unregister(driver_t *drv);
void driver_irq_dispatch(int irq);
