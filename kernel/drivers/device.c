#include "drivers/device.h"
#include "heap.h"
#include "string.h"
#include "stdio.h"

//
// Device Registry
//
static device_t *g_device_list = NULL;
static uint32_t g_device_count = 0;
static uint32_t g_next_device_id = 1;

// Registration
device_t *device_register(device_class_t class, const char *name, void *operations)
{
    device_t *dev = (device_t*)kmalloc(sizeof(device_t));

    if(!dev)
    {
        return NULL;
    }

    memset(dev, 0, sizeof(device_t));

    dev->id = g_next_device_id++;
    dev->class = class;
    dev->operations = operations;
    dev->status = DEVICE_STATUS_OK;
    // No IRQ value by default
    dev->irq = 0xFF;

    if(name)
    {
        strlcpy(dev->name, name, sizeof(dev->name));
    }

    dev->next = g_device_list;
    g_device_list = dev;
    g_device_count++;

    return dev;
}

// Unregister
void device_unregister(device_t *dev)
{
    if(!dev)
    {
        return;
    }

    device_t **dev_p = &g_device_list;

    while(*dev_p)
    {
        if(*dev_p == dev)
        {
            *dev_p = dev->next;
            g_device_count--;

            kfree(dev);

            return;
        }

        dev_p = &(*dev_p)->next;
    }
}


//
// Get Device
//

// Get Device By ID
device_t *device_get_by_id(uint32_t id)
{
    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->id == id)
        {
            return dev;
        }
    }

    return NULL;
}

// Get Device By Name
device_t *device_get_by_name(const char *name)
{
    if(!name)
    {
        return NULL;
    }

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(strcmp(dev->name, name) == 0)
        {
            return dev;
        }
    }

    return NULL;
}


//
// Device Enumerations
//

// Get Device Count
int device_get_count(void)
{
    return (int)g_device_count;
}

// Get Device Count By Class
int device_get_count_by_class(device_class_t class)
{
    int count = 0;

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->class == class)
        {
            count++;
        }
    }

    return count;
}

// Get Device By Index
device_t *device_get_by_index(int index)
{
    int i = 0;

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(i == index)
        {
            return dev;
        }

        i++;
    }

    return NULL;
}

// Enumerate Device Class
int device_enumerate_class(device_class_t class, device_t **out, int max_count)
{
    int count = 0;

    for(device_t *dev = g_device_list; dev && count < max_count; dev = dev->next)
    {
        if(dev->class == class)
        {
            out[count++] = dev;
        }
    }

    return count;
}

// Device Iteration

// Get First Device
device_t *device_first(void)
{
    return g_device_list;
}

// Get Next Device
device_t *device_next(device_t *dev)
{
    return dev ? dev->next : NULL;
}


//
// Userland Stuff
//

// Convert device_t to device_info_t
void device_to_info(device_t *dev, device_info_t *info)
{
    if(!dev || !info)
    {
        return;
    }

    memset(info, 0, sizeof(device_info_t));

    info->id = dev->id;
    info->class = (uint32_t)dev->class;
    info->vendor_id = dev->vendor_id;
    info->device_id = dev->device_id;
    info->bus_type = dev->bus_type;
    info->irq = dev->irq;
    info->status = (uint32_t)dev->status;

    strlcpy(info->name, dev->name, sizeof(info->name));
    strlcpy(info->description, dev->description, sizeof(info->description));
}


//
// Helpers
//

// Device Class Names
const char *device_class_name(device_class_t class)
{
    switch(class)
    {
        case DEVICE_CLASS_INPUT:
            return "Input";
        case DEVICE_CLASS_NETWORK:
            return "Network";
        case DEVICE_CLASS_DISPLAY:
            return "Display";
        case DEVICE_CLASS_TTY:
            return "TTY";
        case DEVICE_CLASS_STORAGE:
            return "Storage";
        case DEVICE_CLASS_SERIAL:
            return "Serial";
        case DEVICE_CLASS_TIMER:
            return "Timer";
        default:
            return "Unknown";
    }
}

// Device Bus Names
const char *device_bus_name(uint8_t bus_type)
{
    switch(bus_type)
    {
        case BUS_TYPE_ISA:
            return "ISA";
        case BUS_TYPE_PCI:
            return "PCI";
        case BUS_TYPE_USB:
            return "USB";
        case BUS_TYPE_PS2:
            return "PS/2";
        case BUS_TYPE_VIRTUAL:
            return "Virtual";
        default:
            return "Unknown";
    }
}
