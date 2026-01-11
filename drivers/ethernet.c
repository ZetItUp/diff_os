#include "drivers/ddf.h"
#include "drivers/device.h"
#include "network/network_interface.h"
#include "network/packet.h"
#include "stdint.h"
#include "stddef.h"

#define ETHERNET_ADDRESS_SIZE   6
#define ETHERNET_HEADER_SIZE    14
#define ETHERNET_MTU            1500
#define ETHERNET_FRAME_MAX      (ETHERNET_HEADER_SIZE + ETHERNET_MTU)
#define ETHERNET_MAX_DEVICES    4

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static volatile kernel_exports_t *kernel = 0;

typedef struct ethernet_adapter
{
    device_t *device;
    network_device_t *operations;
    network_interface_t *interface;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t receive_buffer[ETHERNET_FRAME_MAX];
    uint8_t irqsw_pending;
    uint8_t irq_number;
    int active;
} ethernet_adapter_t;

static ethernet_adapter_t g_adapters[ETHERNET_MAX_DEVICES];

static ethernet_adapter_t *ethernet_find_slot(void)
{
    for (int index = 0; index < ETHERNET_MAX_DEVICES; index++)
    {
        if (!g_adapters[index].active)
        {
            return &g_adapters[index];
        }
    }

    return NULL;
}

static ethernet_adapter_t *ethernet_find_device(device_t *device)
{
    if (!device)
    {
        return NULL;
    }

    for (int index = 0; index < ETHERNET_MAX_DEVICES; index++)
    {
        if (g_adapters[index].active && g_adapters[index].device == device)
        {
            return &g_adapters[index];
        }
    }

    return NULL;
}

static int ethernet_transmit(network_interface_t *interface, packet_buffer_t *packet)
{
    if (!interface || !packet || !packet->data)
    {

        return -1;
    }

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)interface->private_data;

    if (!adapter || !adapter->operations || !adapter->operations->send_packet)
    {

        return -1;
    }

    if (packet->length == 0 || packet->length > ETHERNET_FRAME_MAX)
    {

        return -1;
    }

    return adapter->operations->send_packet(adapter->device, packet->data, (uint16_t)packet->length);
}

static int ethernet_set_promiscuous(network_interface_t *interface, int enabled)
{
    if (!interface)
    {

        return -1;
    }

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)interface->private_data;

    if (!adapter || !adapter->operations || !adapter->operations->set_promiscuous)
    {

        return -1;
    }

    return adapter->operations->set_promiscuous(adapter->device, enabled);
}

static int ethernet_set_multicast(network_interface_t *interface, int enabled)
{
    if (!interface)
    {

        return -1;
    }

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)interface->private_data;

    if (!adapter || !adapter->operations || !adapter->operations->set_multicast)
    {

        return -1;
    }

    return adapter->operations->set_multicast(adapter->device, enabled);
}

static int ethernet_get_link_status(network_interface_t *interface)
{
    if (!interface)
    {

        return 0;
    }

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)interface->private_data;

    if (!adapter || !adapter->operations || !adapter->operations->get_link_status)
    {

        return 0;
    }

    return adapter->operations->get_link_status(adapter->device);
}

static uint32_t ethernet_get_speed(network_interface_t *interface)
{
    if (!interface)
    {

        return 0;
    }

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)interface->private_data;

    if (!adapter || !adapter->operations || !adapter->operations->get_speed)
    {

        return 0;
    }

    return adapter->operations->get_speed(adapter->device);
}

static network_interface_ops_t g_interface_ops =
{
    .transmit = ethernet_transmit,
    .set_promiscuous = ethernet_set_promiscuous,
    .set_multicast = ethernet_set_multicast,
    .get_link_status = ethernet_get_link_status,
    .get_speed = ethernet_get_speed
};

static void ethernet_poll_device(ethernet_adapter_t *adapter)
{
    if (!adapter || !adapter->active || !adapter->operations)
    {

        return;
    }

    if (!adapter->operations->packets_available || !adapter->operations->receive_packet)
    {

        return;
    }

    for (;;)
    {
        if (adapter->operations->packets_available(adapter->device) <= 0)
        {

            break;
        }

        int received = adapter->operations->receive_packet(adapter->device,
            adapter->receive_buffer, ETHERNET_FRAME_MAX);

        if (received <= 0)
        {

            break;
        }

        packet_buffer_t *packet = NULL;

        if (kernel && kernel->packet_buffer_alloc)
        {
            packet = kernel->packet_buffer_alloc((uint32_t)received, 0);
        }

        if (!packet)
        {

            continue;
        }

        for (int copy_index = 0; copy_index < received; copy_index++)
        {
            packet->data[copy_index] = adapter->receive_buffer[copy_index];
        }

        packet->length = (uint32_t)received;
        packet->flags = PACKET_FLAG_INGRESS;

        if (kernel && kernel->timer_now_ms)
        {
            packet->timestamp_ms = (uint32_t)kernel->timer_now_ms();
        }

        if (kernel && kernel->network_interface_receive && adapter->interface)
        {
            kernel->network_interface_receive(adapter->interface, packet);
        }

        if (kernel && kernel->packet_buffer_release)
        {
            kernel->packet_buffer_release(packet);
        }
    }
}

static void ethernet_irqsw_worker(void *context)
{
    ethernet_adapter_t *adapter = (ethernet_adapter_t *)context;

    if (!adapter)
    {

        return;
    }

    adapter->irqsw_pending = 0;

    ethernet_poll_device(adapter);
}

static void ethernet_irq_handler(unsigned irq, void *context)
{
    (void)irq;

    ethernet_adapter_t *adapter = (ethernet_adapter_t *)context;

    if (!adapter || !kernel || !kernel->irqsw_queue)
    {

        return;
    }

    if (!adapter->irqsw_pending)
    {
        adapter->irqsw_pending = 1;
        kernel->irqsw_queue(ethernet_irqsw_worker, adapter);
    }
}

static void ethernet_device_notify(device_t *device, int added)
{
    if (!device)
    {
        return;
    }

    if (added)
    {
        ethernet_adapter_t *adapter = ethernet_find_slot();

        if (!adapter)
        {
            return;
        }

        network_device_t *operations = (network_device_t *)device->operations;

        if (!operations || !operations->get_mac || !operations->send_packet ||
            !operations->receive_packet || !operations->packets_available)
        {
            return;
        }

        adapter->device = device;
        adapter->operations = operations;
        adapter->interface = NULL;
        adapter->active = 1;
        adapter->irqsw_pending = 0;
        adapter->irq_number = device->irq;

        operations->get_mac(device, adapter->mac_address);

        if (kernel && kernel->network_interface_register)
        {
            adapter->interface = kernel->network_interface_register(device,
                &g_interface_ops,
                adapter->mac_address,
                ETHERNET_MTU,
                adapter);
        }

        if (kernel && kernel->irq_register_handler && adapter->irq_number != 0 &&
            adapter->irq_number != 0xFF)
        {
            kernel->irq_register_handler(adapter->irq_number, ethernet_irq_handler, adapter);
        }
    }
    else
    {
        ethernet_adapter_t *adapter = ethernet_find_device(device);

        if (!adapter)
        {
            return;
        }

        if (kernel && kernel->irq_unregister_handler && adapter->irq_number != 0 &&
            adapter->irq_number != 0xFF)
        {
            kernel->irq_unregister_handler(adapter->irq_number, ethernet_irq_handler, adapter);
        }

        if (kernel && kernel->network_interface_unregister && adapter->interface)
        {
            kernel->network_interface_unregister(adapter->interface);
        }

        adapter->active = 0;
        adapter->device = NULL;
        adapter->operations = NULL;
        adapter->interface = NULL;
        adapter->irqsw_pending = 0;
        adapter->irq_number = 0;

        for (int index = 0; index < ETHERNET_ADDRESS_SIZE; index++)
        {
            adapter->mac_address[index] = 0;
        }
    }
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    for (int index = 0; index < ETHERNET_MAX_DEVICES; index++)
    {
        g_adapters[index].active = 0;
        g_adapters[index].device = NULL;
        g_adapters[index].operations = NULL;
        g_adapters[index].interface = NULL;
        g_adapters[index].irqsw_pending = 0;
        g_adapters[index].irq_number = 0;

        for (int mac_index = 0; mac_index < ETHERNET_ADDRESS_SIZE; mac_index++)
        {
            g_adapters[index].mac_address[mac_index] = 0;
        }
    }

    if (kernel && kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(ethernet_device_notify);
    }
}

void ddf_driver_exit(void)
{
    if (kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(ethernet_device_notify);
    }

    for (int index = 0; index < ETHERNET_MAX_DEVICES; index++)
    {
        ethernet_adapter_t *adapter = &g_adapters[index];

        if (adapter->active && kernel && kernel->irq_unregister_handler &&
            adapter->irq_number != 0 && adapter->irq_number != 0xFF)
        {
            kernel->irq_unregister_handler(adapter->irq_number, ethernet_irq_handler, adapter);
        }

        if (adapter->active && kernel && kernel->network_interface_unregister && adapter->interface)
        {
            kernel->network_interface_unregister(adapter->interface);
        }

        adapter->active = 0;
        adapter->device = NULL;
        adapter->operations = NULL;
        adapter->interface = NULL;
        adapter->irqsw_pending = 0;
        adapter->irq_number = 0;
    }
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
