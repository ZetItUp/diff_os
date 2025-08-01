#include "drivers/driver.h"

static driver_t *driver_list[MAX_DRIVERS];
static int driver_count = 0;

void driver_register(driver_t *drv)
{
    if(driver_count < MAX_DRIVERS)
    {
        driver_list[driver_count++] = drv;

        if(drv->init)
        {
            drv->init();
        }
    }
}

void driver_unregister(driver_t *drv)
{
    for(int i = 0; i < driver_count; i++)
    {
        if(driver_list[i] == drv)
        {
            if(drv->exit)
            {
                drv->exit();
            }
                
            // Move the last element to this position
            driver_list[i] = driver_list[driver_count - 1];
            driver_count--;

            return;
        }
    }
}

void driver_irq_dispatch(int irq)
{
    for(int i = 0; i < driver_count; i++)
    {
        if(driver_list[i]->irq_line == irq && driver_list[i]->handle_irq)
        {
            driver_list[i]->handle_irq();

            return;
        }
    }
}
