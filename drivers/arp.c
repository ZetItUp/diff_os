#include "drivers/ddf.h"
#include "drivers/device.h"
#include "network/network_communicator.h"
#include "network/network_interface.h"
#include "network/packet.h"
#include "stdint.h"
#include "stddef.h"

#define ARP_DEFAULT_IP0         192
#define ARP_DEFAULT_IP1         168
#define ARP_DEFAULT_IP2         0
#define ARP_DEFAULT_IP3         2

#define ETHERNET_ADDRESS_SIZE   6
#define ETHERNET_HEADER_SIZE    14
#define ETHERNET_MTU            1500
#define ETHERNET_FRAME_MAX      (ETHERNET_HEADER_SIZE + ETHERNET_MTU)

#define ETHERNET_TYPE_ARP       0x0806

#define ARP_HTYPE_ETHERNET      1
#define ARP_PTYPE_IPV4          0x0800
#define ARP_OP_REQUEST          1
#define ARP_OP_REPLY            2

#define ARP_MAX_DEVICES         4
#define ARP_CACHE_SIZE          8
#define ARP_CACHE_TTL_MS        30000
#define ARP_PENDING_SIZE        8
#define ARP_REQUEST_MIN_MS      1000

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static kernel_exports_t *kernel = NULL;

typedef struct ethernet_header
{
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint8_t ethernet_type[2];
} __attribute__((packed)) ethernet_header_t;

typedef struct arp_packet
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t sender_ip_address[4];
    uint8_t target_mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t target_ip_address[4];
} __attribute__((packed)) arp_packet_t;

typedef struct arp_entry
{
    uint8_t ip_address[4];
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint32_t expires_ms;
    int valid;
} arp_entry_t;

typedef struct arp_pending
{
    uint8_t ip_address[4];
    uint32_t last_request_ms;
    int valid;
} arp_pending_t;

typedef struct arp_device
{
    device_t *device;
    network_device_t *operations;
    network_interface_t *interface;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t ip_address[4];
    int active;
} arp_device_t;

static arp_device_t g_devices[ARP_MAX_DEVICES];
static arp_entry_t g_arp_cache[ARP_CACHE_SIZE];
static arp_pending_t g_arp_pending[ARP_PENDING_SIZE];
static uint8_t g_default_ip[4] = { ARP_DEFAULT_IP0, ARP_DEFAULT_IP1, ARP_DEFAULT_IP2, ARP_DEFAULT_IP3 };

static uint16_t read_be16(const uint8_t *data)
{
    if (!data)
    {
        return 0;
    }

    return (uint16_t)((uint16_t)data[0] << 8 | (uint16_t)data[1]);
}

static void write_be16(uint8_t *data, uint16_t value)
{
    if (!data)
    {
        return;
    }

    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

static int ip_equal(const uint8_t first_ip[4], const uint8_t second_ip[4])
{
    if (!first_ip || !second_ip)
    {
        return 0;
    }

    for (int index = 0; index < 4; index++)
    {
        if (first_ip[index] != second_ip[index])
        {
            return 0;
        }
    }

    return 1;
}

static void ip_copy(uint8_t ip_destination[4], const uint8_t ip_source[4])
{
    for (int index = 0; index < 4; index++)
    {
        ip_destination[index] = ip_source[index];
    }
}

static void mac_copy(uint8_t mac_destination[ETHERNET_ADDRESS_SIZE], const uint8_t mac_source[ETHERNET_ADDRESS_SIZE])
{
    for (int index = 0; index < ETHERNET_ADDRESS_SIZE; index++)
    {
        mac_destination[index] = mac_source[index];
    }
}

static arp_device_t *arp_find_slot(void)
{
    for (int index = 0; index < ARP_MAX_DEVICES; index++)
    {
        if (!g_devices[index].active)
        {
            return &g_devices[index];
        }
    }

    return NULL;
}

static arp_device_t *arp_find_device(device_t *device)
{
    if (!device)
    {
        return NULL;
    }

    for (int index = 0; index < ARP_MAX_DEVICES; index++)
    {
        if (g_devices[index].active && g_devices[index].device == device)
        {
            return &g_devices[index];
        }
    }

    return NULL;
}

static arp_device_t *arp_find_device_for_packet(packet_buffer_t *packet)
{
    if (!packet || !packet->ingress_device)
    {
        return NULL;
    }

    return arp_find_device(packet->ingress_device);
}

static void arp_pending_clear(const uint8_t ip_address[4])
{
    if (!ip_address)
    {
        return;
    }

    for (int index = 0; index < ARP_PENDING_SIZE; index++)
    {
        if (!g_arp_pending[index].valid)
        {
            continue;
        }

        if (ip_equal(g_arp_pending[index].ip_address, ip_address))
        {
            g_arp_pending[index].valid = 0;

            return;
        }
    }
}

static void arp_cache_put(const uint8_t ip_address[4], const uint8_t mac_address[ETHERNET_ADDRESS_SIZE],
    uint32_t current_time_ms)
{
    if (!ip_address || !mac_address)
    {
        return;
    }

    int slot = -1;

    for (int index = 0; index < ARP_CACHE_SIZE; index++)
    {
        if (g_arp_cache[index].valid && ip_equal(g_arp_cache[index].ip_address, ip_address))
        {
            slot = index;

            break;
        }

        if (!g_arp_cache[index].valid && slot < 0)
        {
            slot = index;
        }
    }

    if (slot < 0)
    {
        return;
    }

    ip_copy(g_arp_cache[slot].ip_address, ip_address);
    mac_copy(g_arp_cache[slot].mac_address, mac_address);
    g_arp_cache[slot].expires_ms = current_time_ms + ARP_CACHE_TTL_MS;
    g_arp_cache[slot].valid = 1;
}

static network_interface_t *arp_get_interface(arp_device_t *device_entry)
{
    if (!device_entry)
    {
        return NULL;
    }

    if (device_entry->interface)
    {
        return device_entry->interface;
    }

    if (kernel && kernel->network_interface_get_by_device)
    {
        return kernel->network_interface_get_by_device(device_entry->device);
    }

    return NULL;
}

static int arp_send_frame(arp_device_t *device_entry, const uint8_t *frame, uint16_t frame_length)
{
    if (!device_entry || !frame || frame_length == 0)
    {
        return -1;
    }

    network_interface_t *interface = arp_get_interface(device_entry);

    if (interface && kernel && kernel->network_communicator_transmit)
    {
        packet_buffer_t *packet = NULL;

        if (kernel->packet_buffer_alloc)
        {
            packet = kernel->packet_buffer_alloc(frame_length, 0);
        }

        if (!packet)
        {

            return -1;
        }

        for (uint16_t copy_index = 0; copy_index < frame_length; copy_index++)
        {
            packet->data[copy_index] = frame[copy_index];
        }

        packet->length = frame_length;
        packet->flags = PACKET_FLAG_EGRESS;
        packet->protocol = ETHERNET_TYPE_ARP;

        if (kernel->timer_now_ms)
        {
            packet->timestamp_ms = (uint32_t)kernel->timer_now_ms();
        }

        int result = kernel->network_communicator_transmit(interface, packet);

        if (kernel->packet_buffer_release)
        {
            kernel->packet_buffer_release(packet);
        }

        return result;
    }

    if (device_entry->operations && device_entry->operations->send_packet)
    {
        return device_entry->operations->send_packet(device_entry->device, frame, frame_length);
    }

    return -1;
}

static void __attribute__((unused)) arp_send_request(arp_device_t *device_entry,
    const uint8_t target_ip_address[4],
    uint32_t current_time_ms)
{
    if (!device_entry || !target_ip_address)
    {
        return;
    }

    uint8_t request_frame[ETHERNET_HEADER_SIZE + sizeof(arp_packet_t)];
    ethernet_header_t *ethernet_header = (ethernet_header_t *)request_frame;
    arp_packet_t *arp_packet = (arp_packet_t *)(request_frame + ETHERNET_HEADER_SIZE);
    uint8_t broadcast[ETHERNET_ADDRESS_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    mac_copy(ethernet_header->destination, broadcast);
    mac_copy(ethernet_header->source, device_entry->mac_address);
    write_be16(ethernet_header->ethernet_type, ETHERNET_TYPE_ARP);

    write_be16((uint8_t *)&arp_packet->hardware_type, ARP_HTYPE_ETHERNET);
    write_be16((uint8_t *)&arp_packet->protocol_type, ARP_PTYPE_IPV4);
    arp_packet->hardware_length = ETHERNET_ADDRESS_SIZE;
    arp_packet->protocol_length = 4;
    write_be16((uint8_t *)&arp_packet->operation, ARP_OP_REQUEST);

    mac_copy(arp_packet->sender_mac_address, device_entry->mac_address);
    ip_copy(arp_packet->sender_ip_address, device_entry->ip_address);
    ip_copy(arp_packet->target_ip_address, target_ip_address);

    for (int index = 0; index < ETHERNET_ADDRESS_SIZE; index++)
    {
        arp_packet->target_mac_address[index] = 0;
    }

    int pending_slot = -1;

    for (int index = 0; index < ARP_PENDING_SIZE; index++)
    {
        if (g_arp_pending[index].valid && ip_equal(g_arp_pending[index].ip_address, target_ip_address))
        {
            if (current_time_ms - g_arp_pending[index].last_request_ms < ARP_REQUEST_MIN_MS)
            {
                return;
            }

            pending_slot = index;

            break;
        }

        if (!g_arp_pending[index].valid && pending_slot < 0)
        {
            pending_slot = index;
        }
    }

    if (pending_slot < 0)
    {
        return;
    }

    ip_copy(g_arp_pending[pending_slot].ip_address, target_ip_address);
    g_arp_pending[pending_slot].last_request_ms = current_time_ms;
    g_arp_pending[pending_slot].valid = 1;

    arp_send_frame(device_entry, request_frame, sizeof(request_frame));
}

static void arp_send_reply(arp_device_t *device_entry, const uint8_t target_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t target_ip_address[4])
{
    if (!device_entry || !target_mac || !target_ip_address)
    {
        return;
    }

    uint8_t reply_frame[ETHERNET_HEADER_SIZE + sizeof(arp_packet_t)];
    ethernet_header_t *ethernet_header = (ethernet_header_t *)reply_frame;
    arp_packet_t *arp_packet = (arp_packet_t *)(reply_frame + ETHERNET_HEADER_SIZE);

    mac_copy(ethernet_header->destination, target_mac);
    mac_copy(ethernet_header->source, device_entry->mac_address);
    write_be16(ethernet_header->ethernet_type, ETHERNET_TYPE_ARP);

    write_be16((uint8_t *)&arp_packet->hardware_type, ARP_HTYPE_ETHERNET);
    write_be16((uint8_t *)&arp_packet->protocol_type, ARP_PTYPE_IPV4);
    arp_packet->hardware_length = ETHERNET_ADDRESS_SIZE;
    arp_packet->protocol_length = 4;
    write_be16((uint8_t *)&arp_packet->operation, ARP_OP_REPLY);

    mac_copy(arp_packet->sender_mac_address, device_entry->mac_address);
    mac_copy(arp_packet->target_mac_address, target_mac);
    ip_copy(arp_packet->sender_ip_address, device_entry->ip_address);
    ip_copy(arp_packet->target_ip_address, target_ip_address);

    arp_send_frame(device_entry, reply_frame, sizeof(reply_frame));
}

static void arp_handle_packet(packet_buffer_t *packet)
{
    if (!packet || !packet->data || packet->length < ETHERNET_HEADER_SIZE + sizeof(arp_packet_t))
    {
        return;
    }

    arp_device_t *device_entry = arp_find_device_for_packet(packet);

    if (!device_entry)
    {
        return;
    }

    ethernet_header_t *ethernet_header = (ethernet_header_t *)packet->data;
    uint16_t ethernet_type = read_be16(ethernet_header->ethernet_type);

    if (ethernet_type != ETHERNET_TYPE_ARP)
    {
        return;
    }

    arp_packet_t *arp_packet = (arp_packet_t *)(packet->data + ETHERNET_HEADER_SIZE);

    if (read_be16((const uint8_t *)&arp_packet->hardware_type) != ARP_HTYPE_ETHERNET)
    {
        return;
    }

    if (read_be16((const uint8_t *)&arp_packet->protocol_type) != ARP_PTYPE_IPV4)
    {
        return;
    }

    if (arp_packet->hardware_length != ETHERNET_ADDRESS_SIZE || arp_packet->protocol_length != 4)
    {
        return;
    }

    uint16_t operation = read_be16((const uint8_t *)&arp_packet->operation);

    uint32_t current_time_ms = 0;
    if (kernel && kernel->timer_now_ms)
    {
        current_time_ms = (uint32_t)kernel->timer_now_ms();
    }

    arp_cache_put(arp_packet->sender_ip_address, arp_packet->sender_mac_address, current_time_ms);
    arp_pending_clear(arp_packet->sender_ip_address);

    if (operation == ARP_OP_REQUEST &&
        ip_equal(arp_packet->target_ip_address, device_entry->ip_address))
    {
        arp_send_reply(device_entry, arp_packet->sender_mac_address, arp_packet->sender_ip_address);
    }
}

static void arp_receive(packet_buffer_t *packet, void *context)
{
    (void)context;

    arp_handle_packet(packet);
}

static void arp_device_notify(device_t *device, int is_added)
{
    if (!device)
    {
        return;
    }

    if (is_added)
    {
        arp_device_t *device_entry = arp_find_slot();

        if (!device_entry)
        {
            return;
        }

        network_device_t *operations = (network_device_t *)device->operations;

        if (!operations || !operations->get_mac || !operations->send_packet)
        {
            return;
        }

        device_entry->device = device;
        device_entry->operations = operations;
        device_entry->interface = NULL;
        device_entry->active = 1;

        operations->get_mac(device, device_entry->mac_address);
        ip_copy(device_entry->ip_address, g_default_ip);

        if (kernel && kernel->network_interface_get_by_device)
        {
            device_entry->interface = kernel->network_interface_get_by_device(device);
        }
    }
    else
    {
        arp_device_t *device_entry = arp_find_device(device);

        if (!device_entry)
        {
            return;
        }

        device_entry->active = 0;
        device_entry->device = NULL;
        device_entry->operations = NULL;
        device_entry->interface = NULL;
    }
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    for (int index = 0; index < ARP_MAX_DEVICES; index++)
    {
        g_devices[index].active = 0;
        g_devices[index].device = NULL;
        g_devices[index].operations = NULL;
        g_devices[index].interface = NULL;

        for (int mac_index = 0; mac_index < ETHERNET_ADDRESS_SIZE; mac_index++)
        {
            g_devices[index].mac_address[mac_index] = 0;
        }

        for (int ip_index = 0; ip_index < 4; ip_index++)
        {
            g_devices[index].ip_address[ip_index] = 0;
        }
    }

    for (int index = 0; index < ARP_CACHE_SIZE; index++)
    {
        g_arp_cache[index].valid = 0;
        g_arp_cache[index].expires_ms = 0;
    }

    for (int index = 0; index < ARP_PENDING_SIZE; index++)
    {
        g_arp_pending[index].valid = 0;
        g_arp_pending[index].last_request_ms = 0;
    }

    if (kernel && kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(arp_device_notify);
    }

    if (kernel && kernel->network_communicator_register_ethernet_type)
    {
        kernel->network_communicator_register_ethernet_type(ETHERNET_TYPE_ARP, arp_receive, NULL);
    }
}

void ddf_driver_exit(void)
{
    if (kernel && kernel->network_communicator_unregister_ethernet_type)
    {
        kernel->network_communicator_unregister_ethernet_type(ETHERNET_TYPE_ARP, arp_receive, NULL);
    }

    if (kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(arp_device_notify);
    }

    for (int index = 0; index < ARP_MAX_DEVICES; index++)
    {
        g_devices[index].active = 0;
        g_devices[index].device = NULL;
        g_devices[index].operations = NULL;
        g_devices[index].interface = NULL;
    }
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
