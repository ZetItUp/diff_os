#include "network/network_communicator.h"
#include "system/spinlock.h"

#define MAX_NETWORK_COMMUNICATOR_HANDLERS 16

typedef struct network_communicator_entry
{
    uint16_t ethernet_type;
    network_communicator_handler_t handler;
    void *context;
} network_communicator_entry_t;

static network_communicator_entry_t g_network_communicator_entries[MAX_NETWORK_COMMUNICATOR_HANDLERS];
static int g_network_communicator_count = 0;
static spinlock_t g_network_communicator_lock;
static int g_network_communicator_lock_inited = 0;

static void network_communicator_lock_init(void)
{
    if (!g_network_communicator_lock_inited)
    {
        spinlock_init(&g_network_communicator_lock);
        g_network_communicator_lock_inited = 1;
    }
}

int network_communicator_register_ethernet_type(uint16_t ethernet_type,
    network_communicator_handler_t handler,
    void *context)
{
    if (!handler)
    {

        return -1;
    }

    network_communicator_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_communicator_lock, &flags);

    for (int index = 0; index < g_network_communicator_count; index++)
    {
        network_communicator_entry_t *entry = &g_network_communicator_entries[index];

        if (entry->ethernet_type == ethernet_type && entry->handler == handler &&
            entry->context == context)
        {
            spin_unlock_irqrestore(&g_network_communicator_lock, flags);

            return 0;
        }
    }

    if (g_network_communicator_count >= MAX_NETWORK_COMMUNICATOR_HANDLERS)
    {
        spin_unlock_irqrestore(&g_network_communicator_lock, flags);

        return -1;
    }

    network_communicator_entry_t *new_entry =
        &g_network_communicator_entries[g_network_communicator_count++];
    new_entry->ethernet_type = ethernet_type;
    new_entry->handler = handler;
    new_entry->context = context;

    spin_unlock_irqrestore(&g_network_communicator_lock, flags);

    return 0;
}

int network_communicator_unregister_ethernet_type(uint16_t ethernet_type,
    network_communicator_handler_t handler,
    void *context)
{
    if (!handler)
    {

        return -1;
    }

    network_communicator_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_communicator_lock, &flags);

    for (int index = 0; index < g_network_communicator_count; index++)
    {
        network_communicator_entry_t *entry = &g_network_communicator_entries[index];

        if (entry->ethernet_type == ethernet_type && entry->handler == handler &&
            entry->context == context)
        {
            for (int move_index = index;
                move_index < g_network_communicator_count - 1;
                move_index++)
            {
                g_network_communicator_entries[move_index] =
                    g_network_communicator_entries[move_index + 1];
            }

            g_network_communicator_count--;

            spin_unlock_irqrestore(&g_network_communicator_lock, flags);

            return 0;
        }
    }

    spin_unlock_irqrestore(&g_network_communicator_lock, flags);

    return -1;
}

int network_communicator_receive(network_interface_t *interface, packet_buffer_t *packet)
{
    if (!interface || !packet || !packet->data)
    {

        return -1;
    }

    if (packet->length < 14)
    {

        return -1;
    }

    packet->ingress_device = interface->device;

    uint8_t *data = packet->data;
    uint16_t ethernet_type = (uint16_t)((uint16_t)data[12] << 8 | data[13]);

    network_communicator_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_communicator_lock, &flags);

    for (int index = 0; index < g_network_communicator_count; index++)
    {
        network_communicator_entry_t *entry = &g_network_communicator_entries[index];

        if (entry->ethernet_type == ethernet_type && entry->handler)
        {
            entry->handler(packet, entry->context);
        }
    }

    spin_unlock_irqrestore(&g_network_communicator_lock, flags);

    return 0;
}

int network_communicator_transmit(network_interface_t *interface, packet_buffer_t *packet)
{
    if (!interface || !interface->ops || !interface->ops->transmit || !packet)
    {

        return -1;
    }

    packet->egress_device = interface->device;

    return interface->ops->transmit(interface, packet);
}
