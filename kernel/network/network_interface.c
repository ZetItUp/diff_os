#include "network/network_interface.h"
#include "network/network_communicator.h"
#include "heap.h"
#include "string.h"
#include "system/spinlock.h"

#define MAX_NETWORK_INTERFACES 8

static network_interface_t *g_interfaces[MAX_NETWORK_INTERFACES];
static spinlock_t g_interface_lock;
static int g_interface_lock_inited = 0;

static void interface_lock_init(void)
{
    if (!g_interface_lock_inited)
    {
        spinlock_init(&g_interface_lock);
        g_interface_lock_inited = 1;
    }
}

network_interface_t *network_interface_register(struct device *device,
    network_interface_ops_t *ops,
    const uint8_t mac_address[6],
    uint32_t mtu,
    void *private_data)
{
    if (!device || !ops || !mac_address || mtu == 0)
    {

        return NULL;
    }

    network_interface_t *interface = kmalloc(sizeof(*interface));
    if (!interface)
    {

        return NULL;
    }

    memset(interface, 0, sizeof(*interface));
    interface->device = device;
    interface->ops = ops;
    interface->mtu = mtu;
    interface->private_data = private_data;

    for (int index = 0; index < 6; index++)
    {
        interface->mac_address[index] = mac_address[index];
    }

    interface_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_interface_lock, &flags);

    int slot_found = 0;
    for (int interface_index = 0; interface_index < MAX_NETWORK_INTERFACES; interface_index++)
    {
        if (!g_interfaces[interface_index])
        {
            g_interfaces[interface_index] = interface;
            slot_found = 1;

            break;
        }
    }

    spin_unlock_irqrestore(&g_interface_lock, flags);

    if (!slot_found)
    {
        kfree(interface);

        return NULL;
    }

    return interface;
}

void network_interface_unregister(network_interface_t *interface)
{
    if (!interface)
    {

        return;
    }

    interface_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_interface_lock, &flags);

    for (int interface_index = 0; interface_index < MAX_NETWORK_INTERFACES; interface_index++)
    {
        if (g_interfaces[interface_index] == interface)
        {
            g_interfaces[interface_index] = NULL;

            break;
        }
    }

    spin_unlock_irqrestore(&g_interface_lock, flags);

    kfree(interface);
}

network_interface_t *network_interface_get_primary(void)
{
    network_interface_t *interface = NULL;

    interface_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_interface_lock, &flags);

    for (int index = 0; index < MAX_NETWORK_INTERFACES; index++)
    {
        if (g_interfaces[index])
        {
            interface = g_interfaces[index];

            break;
        }
    }

    spin_unlock_irqrestore(&g_interface_lock, flags);

    return interface;
}

network_interface_t *network_interface_get_by_device(struct device *device)
{
    if (!device)
    {

        return NULL;
    }

    network_interface_t *interface = NULL;

    interface_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_interface_lock, &flags);

    for (int index = 0; index < MAX_NETWORK_INTERFACES; index++)
    {
        network_interface_t *candidate = g_interfaces[index];

        if (candidate && candidate->device == device)
        {
            interface = candidate;

            break;
        }
    }

    spin_unlock_irqrestore(&g_interface_lock, flags);

    return interface;
}

int network_interface_receive(network_interface_t *interface, packet_buffer_t *packet)
{
    if (!interface || !packet)
    {

        return -1;
    }

    return network_communicator_receive(interface, packet);
}
