#include "drivers/device.h"
#include "heap.h"
#include "string.h"
#include "stdio.h"
#include "system/spinlock.h"

//
// Device Registry
//
static device_t *g_device_list = NULL;
static uint32_t g_device_count = 0;
static uint32_t g_next_device_id = 1;
static spinlock_t g_device_lock;
static int g_device_lock_inited = 0;

// Network device listeners
#define MAX_NETWORK_LISTENERS 8
#define MAX_NETWORK_NOTIFY_DEVICES 8

static network_device_notify_t g_network_listeners[MAX_NETWORK_LISTENERS];
static int g_network_listener_count = 0;
static spinlock_t g_network_listener_lock;
static int g_network_listener_lock_inited = 0;

//
// Class / Bus Registry
//
typedef struct device_class_entry
{
    device_class_t class;
    char name[DEVICE_CLASS_NAME_LEN];
    struct device_class_entry *next;
} device_class_entry_t;

typedef struct device_bus_entry
{
    uint8_t bus_type;
    char name[DEVICE_BUS_NAME_LEN];
    struct device_bus_entry *next;
} device_bus_entry_t;

static device_class_entry_t *g_class_list = NULL;
static device_bus_entry_t *g_bus_list = NULL;
static spinlock_t g_class_lock;
static spinlock_t g_bus_lock;
static int g_registry_locks_inited = 0;

static void device_lock_init(void)
{
    if(!g_device_lock_inited)
    {
        spinlock_init(&g_device_lock);
        g_device_lock_inited = 1;
    }
}

static void device_registry_lock_init(void)
{
    if(!g_registry_locks_inited)
    {
        spinlock_init(&g_class_lock);
        spinlock_init(&g_bus_lock);
        g_registry_locks_inited = 1;
    }
}

static void network_listener_lock_init(void)
{
    if(!g_network_listener_lock_inited)
    {
        spinlock_init(&g_network_listener_lock);
        g_network_listener_lock_inited = 1;
    }
}

static void notify_network_listeners(device_t *dev, int added)
{
    network_device_notify_t listeners[MAX_NETWORK_LISTENERS];
    int count = 0;

    if(!dev)
    {

        return;
    }

    network_listener_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_listener_lock, &flags);

    for(int i = 0; i < g_network_listener_count; i++)
    {
        listeners[count++] = g_network_listeners[i];
    }

    spin_unlock_irqrestore(&g_network_listener_lock, flags);

    for(int i = 0; i < count; i++)
    {
        listeners[i](dev, added);
    }
}

static int gather_network_devices(device_t **out, int max_count)
{
    if(!out || max_count <= 0)
    {

        return 0;
    }

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    int count = 0;

    for(device_t *dev = g_device_list; dev && count < max_count; dev = dev->next)
    {
        if(dev->class == DEVICE_CLASS_NETWORK)
        {
            dev->refcount++;
            out[count++] = dev;
        }
    }

    spin_unlock_irqrestore(&g_device_lock, flags);

    return count;
}

int device_register_network_listener(network_device_notify_t callback)
{
    if(!callback)
    {

        return -1;
    }

    network_listener_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_listener_lock, &flags);

    for(int i = 0; i < g_network_listener_count; i++)
    {
        if(g_network_listeners[i] == callback)
        {
            spin_unlock_irqrestore(&g_network_listener_lock, flags);

            return 0;
        }
    }

    if(g_network_listener_count >= MAX_NETWORK_LISTENERS)
    {
        spin_unlock_irqrestore(&g_network_listener_lock, flags);

        return -1;
    }

    g_network_listeners[g_network_listener_count++] = callback;

    spin_unlock_irqrestore(&g_network_listener_lock, flags);

    device_t *devices[MAX_NETWORK_NOTIFY_DEVICES];
    int device_count = gather_network_devices(devices, MAX_NETWORK_NOTIFY_DEVICES);

    for(int i = 0; i < device_count; i++)
    {
        callback(devices[i], 1);
        device_put(devices[i]);
    }

    return 0;
}

int device_unregister_network_listener(network_device_notify_t callback)
{
    if(!callback)
    {

        return -1;
    }

    network_listener_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_listener_lock, &flags);

    for(int i = 0; i < g_network_listener_count; i++)
    {
        if(g_network_listeners[i] == callback)
        {
            for(int j = i; j < g_network_listener_count - 1; j++)
            {
                g_network_listeners[j] = g_network_listeners[j + 1];
            }

            g_network_listener_count--;

            spin_unlock_irqrestore(&g_network_listener_lock, flags);

            return 0;
        }
    }

    spin_unlock_irqrestore(&g_network_listener_lock, flags);

    return -1;
}

int device_class_register(device_class_t class, const char *name)
{
    device_registry_lock_init();

    if(!name)
    {
        return -1;
    }

    uint32_t flags = 0;
    spin_lock_irqsave(&g_class_lock, &flags);

    for(device_class_entry_t *entry = g_class_list; entry; entry = entry->next)
    {
        if(entry->class == class)
        {
            strlcpy(entry->name, name, sizeof(entry->name));
            spin_unlock_irqrestore(&g_class_lock, flags);
            return 0;
        }
    }

    device_class_entry_t *entry = (device_class_entry_t*)kmalloc(sizeof(device_class_entry_t));
    if(!entry)
    {
        spin_unlock_irqrestore(&g_class_lock, flags);
        return -1;
    }

    entry->class = class;
    strlcpy(entry->name, name, sizeof(entry->name));
    entry->next = g_class_list;
    g_class_list = entry;

    spin_unlock_irqrestore(&g_class_lock, flags);
    return 0;
}

int device_bus_register(uint8_t bus_type, const char *name)
{
    device_registry_lock_init();

    if(!name)
    {
        return -1;
    }

    uint32_t flags = 0;
    spin_lock_irqsave(&g_bus_lock, &flags);

    for(device_bus_entry_t *entry = g_bus_list; entry; entry = entry->next)
    {
        if(entry->bus_type == bus_type)
        {
            strlcpy(entry->name, name, sizeof(entry->name));
            spin_unlock_irqrestore(&g_bus_lock, flags);
            return 0;
        }
    }

    device_bus_entry_t *entry = (device_bus_entry_t*)kmalloc(sizeof(device_bus_entry_t));
    if(!entry)
    {
        spin_unlock_irqrestore(&g_bus_lock, flags);
        return -1;
    }

    entry->bus_type = bus_type;
    strlcpy(entry->name, name, sizeof(entry->name));
    entry->next = g_bus_list;
    g_bus_list = entry;

    spin_unlock_irqrestore(&g_bus_lock, flags);
    return 0;
}

int device_class_unregister(device_class_t class)
{
    device_lock_init();
    device_registry_lock_init();

    uint32_t dev_flags = 0;
    spin_lock_irqsave(&g_device_lock, &dev_flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->class == class)
        {
            spin_unlock_irqrestore(&g_device_lock, dev_flags);
            return -1;
        }
    }

    uint32_t cls_flags = 0;
    spin_lock_irqsave(&g_class_lock, &cls_flags);

    device_class_entry_t **entry_p = &g_class_list;
    while(*entry_p)
    {
        if((*entry_p)->class == class)
        {
            device_class_entry_t *entry = *entry_p;
            *entry_p = entry->next;
            spin_unlock_irqrestore(&g_class_lock, cls_flags);
            spin_unlock_irqrestore(&g_device_lock, dev_flags);
            kfree(entry);
            return 0;
        }

        entry_p = &(*entry_p)->next;
    }

    spin_unlock_irqrestore(&g_class_lock, cls_flags);
    spin_unlock_irqrestore(&g_device_lock, dev_flags);

    return -1;
}

int device_bus_unregister(uint8_t bus_type)
{
    device_lock_init();
    device_registry_lock_init();

    uint32_t dev_flags = 0;
    spin_lock_irqsave(&g_device_lock, &dev_flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->bus_type == bus_type)
        {
            spin_unlock_irqrestore(&g_device_lock, dev_flags);
            return -1;
        }
    }

    uint32_t bus_flags = 0;
    spin_lock_irqsave(&g_bus_lock, &bus_flags);

    device_bus_entry_t **entry_p = &g_bus_list;
    while(*entry_p)
    {
        if((*entry_p)->bus_type == bus_type)
        {
            device_bus_entry_t *entry = *entry_p;
            *entry_p = entry->next;
            spin_unlock_irqrestore(&g_bus_lock, bus_flags);
            spin_unlock_irqrestore(&g_device_lock, dev_flags);
            kfree(entry);
            return 0;
        }

        entry_p = &(*entry_p)->next;
    }

    spin_unlock_irqrestore(&g_bus_lock, bus_flags);
    spin_unlock_irqrestore(&g_device_lock, dev_flags);

    return -1;
}

const char *device_class_name(device_class_t class)
{
    device_registry_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_class_lock, &flags);

    for(device_class_entry_t *entry = g_class_list; entry; entry = entry->next)
    {
        if(entry->class == class)
        {
            spin_unlock_irqrestore(&g_class_lock, flags);
            return entry->name;
        }
    }

    spin_unlock_irqrestore(&g_class_lock, flags);
    return "Unknown";
}

const char *device_bus_name(uint8_t bus_type)
{
    device_registry_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_bus_lock, &flags);

    for(device_bus_entry_t *entry = g_bus_list; entry; entry = entry->next)
    {
        if(entry->bus_type == bus_type)
        {
            spin_unlock_irqrestore(&g_bus_lock, flags);
            return entry->name;
        }
    }

    spin_unlock_irqrestore(&g_bus_lock, flags);
    return "Unknown";
}

// Registration
device_t *device_register(device_class_t class, const char *name, void *operations)
{
    device_lock_init();

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
    dev->refcount = 1;
    // No IRQ value by default
    dev->irq = 0xFF;

    if(name)
    {
        strlcpy(dev->name, name, sizeof(dev->name));
    }

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    dev->next = g_device_list;
    g_device_list = dev;
    g_device_count++;

    spin_unlock_irqrestore(&g_device_lock, flags);

    if(class == DEVICE_CLASS_NETWORK)
    {
        notify_network_listeners(dev, 1);
    }

    return dev;
}

// Unregister
void device_unregister(device_t *dev)
{
    if(!dev)
    {
        return;
    }

    device_lock_init();

    device_t **dev_p = &g_device_list;

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    while(*dev_p)
    {
        if(*dev_p == dev)
        {
            *dev_p = dev->next;
            g_device_count--;

            dev->removing = 1;
            dev->status = DEVICE_STATUS_DISABLED;

            spin_unlock_irqrestore(&g_device_lock, flags);

            if(dev->class == DEVICE_CLASS_NETWORK)
            {
                notify_network_listeners(dev, 0);
            }

            device_put(dev);

            return;
        }

        dev_p = &(*dev_p)->next;
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
}


//
// Get Device
//

// Get Device By ID
device_t *device_get_by_id(uint32_t id)
{
    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->id == id)
        {
            dev->refcount++;
            spin_unlock_irqrestore(&g_device_lock, flags);
            return dev;
        }
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
    return NULL;
}

// Get Device By Name
device_t *device_get_by_name(const char *name)
{
    if(!name)
    {
        return NULL;
    }

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(strcmp(dev->name, name) == 0)
        {
            dev->refcount++;
            spin_unlock_irqrestore(&g_device_lock, flags);
            return dev;
        }
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
    return NULL;
}


//
// Device Enumerations
//

// Get Device Count
int device_get_count(void)
{
    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);
    int count = (int)g_device_count;
    spin_unlock_irqrestore(&g_device_lock, flags);

    return count;
}

// Get Device Count By Class
int device_get_count_by_class(device_class_t class)
{
    int count = 0;

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(dev->class == class)
        {
            count++;
        }
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
    return count;
}

// Get Device By Index
device_t *device_get_by_index(int index)
{
    if(index < 0)
    {
        return NULL;
    }

    int i = 0;

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    for(device_t *dev = g_device_list; dev; dev = dev->next)
    {
        if(i == index)
        {
            dev->refcount++;
            spin_unlock_irqrestore(&g_device_lock, flags);
            return dev;
        }

        i++;
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
    return NULL;
}

// Enumerate Device Class
int device_enumerate_class(device_class_t class, device_t **out, int max_count)
{
    if(!out || max_count <= 0)
    {
        return 0;
    }

    int count = 0;

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    for(device_t *dev = g_device_list; dev && count < max_count; dev = dev->next)
    {
        if(dev->class == class)
        {
            dev->refcount++;
            out[count++] = dev;
        }
    }

    spin_unlock_irqrestore(&g_device_lock, flags);
    return count;
}

// Device Iteration

// Get First Device
device_t *device_first(void)
{
    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);
    device_t *dev = g_device_list;
    if(dev)
    {
        dev->refcount++;
    }
    spin_unlock_irqrestore(&g_device_lock, flags);

    return dev;
}

// Get Next Device
device_t *device_next(device_t *dev)
{
    if(!dev)
    {
        return NULL;
    }

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);
    device_t *next = dev->next;
    if(next)
    {
        next->refcount++;
    }
    spin_unlock_irqrestore(&g_device_lock, flags);

    return next;
}

void device_put(device_t *dev)
{
    if(!dev)
    {
        return;
    }

    device_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_device_lock, &flags);

    if(dev->refcount > 0)
    {
        dev->refcount--;
    }

    int do_free = (dev->refcount == 0 && dev->removing);

    spin_unlock_irqrestore(&g_device_lock, flags);

    if(do_free)
    {
        if(dev->stop)
        {
            dev->stop(dev);
        }

        if(dev->cleanup)
        {
            dev->cleanup(dev);
        }

        kfree(dev);
    }
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
