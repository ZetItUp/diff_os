#include "drivers/ddf.h"
#include "drivers/device.h"
#include "stdint.h"
#include "stddef.h"
#include "string.h"

#define ARP_DEFAULT_IP0         192         // Default IP octet 0
#define ARP_DEFAULT_IP1         168         // Default IP octet 1
#define ARP_DEFAULT_IP2         0           // Default IP octet 2
#define ARP_DEFAULT_IP3         2           // Default IP octet 3

#define ETHERNET_ADDRESS_SIZE   6           // MAC address length
#define ETHERNET_HEADER_SIZE    14          // Ethernet header length
#define ETHERNET_MTU            1500        // Maximum Transmission Unit
#define ETHERNET_FRAME_MAX      (ETHERNET_HEADER_SIZE + ETHERNET_MTU) // Max frame size

#define ETHERNET_TYPE_ARP       0x0806      // ARP ethertype

#define ARP_HTYPE_ETHERNET      1           // Ethernet hardware type
#define ARP_PTYPE_IPV4          0x0800      // IPv4 protocol type
#define ARP_OP_REQUEST          1           // ARP request opcode
#define ARP_OP_REPLY            2           // ARP reply opcode

#define ARP_MAX_DEVICES         4           // Max devices
#define ARP_CACHE_SIZE          8           // Cache entries
#define ARP_CACHE_TTL_MS        30000       // Cache lifetime
#define ARP_PENDING_SIZE        8           // Pending request slots
#define ARP_REQUEST_MIN_MS      1000        // Min time between requests

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static kernel_exports_t *kernel = NULL;

// Ethernet Header
typedef struct ethernet_header
{
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint8_t ethertype[2];
} __attribute__((packed)) ethernet_header_t;

// ARP Packet
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

// ARP Cache Entry
typedef struct arp_entry
{
    uint8_t ip_address[4];
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint32_t expires_ms;
    int valid;
} arp_entry_t;

// ARP Pending Entry
typedef struct arp_pending
{
    uint8_t ip_address[4];
    uint32_t last_request_ms;
    int valid;
} arp_pending_t;

// ARP Device
typedef struct arp_device
{
    device_t *device;
    network_device_t *operations;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t ip_address[4];
    uint8_t receive_buffer[ETHERNET_FRAME_MAX];
    uint8_t irqsw_pending;
    uint8_t irq_number;
    int active;
} arp_device_t;

// Global State
static arp_device_t g_devices[ARP_MAX_DEVICES];
static arp_entry_t g_arp_cache[ARP_CACHE_SIZE];
static arp_pending_t g_arp_pending[ARP_PENDING_SIZE];
static uint8_t g_default_ip[4] = { ARP_DEFAULT_IP0, ARP_DEFAULT_IP1, ARP_DEFAULT_IP2, ARP_DEFAULT_IP3 };


// Helpers

// Read Data With Big Endian 16-bits
static uint16_t read_be16(const uint8_t *data)
{
    if (!data)
    {
        return 0;
    }

    return (uint16_t)((uint16_t)data[0] << 8 | (uint16_t)data[1]);
}

// Write Data With Big Endian 16-bits
static void write_be16(uint8_t *data, uint16_t value)
{
    if (!data)
    {
        return;
    }

    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

// Check if two IPs match
static int ip_equal(const uint8_t first_ip[4], const uint8_t second_ip[4])
{
    if (!first_ip || !second_ip)
    {
        return 0;
    }

    for (int i = 0; i < 4; i++)
    {
        if (first_ip[i] != second_ip[i])
        {
            return 0;
        }
    }

    return 1;
}

// Copy IP Address
static void ip_copy(uint8_t ip_destination[4], const uint8_t ip_source[4])
{
    for (int i = 0; i < 4; i++)
    {
        ip_destination[i] = ip_source[i];
    }
}

// Copy MAC Address
static void mac_copy(uint8_t mac_destination[ETHERNET_ADDRESS_SIZE], const uint8_t mac_source[ETHERNET_ADDRESS_SIZE])
{
    for (int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        mac_destination[i] = mac_source[i];
    }
}

// Check if IP is set
static int ip_is_zero(const uint8_t ip_address[4])
{
    for (int i = 0; i < 4; i++)
    {
        if (ip_address[i] != 0)
        {
            return 0;
        }
    }

    return 1;
}

// Find Free Device Slot
static arp_device_t *arp_find_slot(void)
{
    for (int i = 0; i < ARP_MAX_DEVICES; i++)
    {
        if (!g_devices[i].active)
        {
            return &g_devices[i];
        }
    }

    return NULL;
}

// Find ARP Device
static arp_device_t *arp_find_device(device_t *device)
{
    if (!device)
    {
        return NULL;
    }

    for (int i = 0; i < ARP_MAX_DEVICES; i++)
    {
        if (g_devices[i].active && g_devices[i].device == device)
        {
            return &g_devices[i];
        }
    }

    return NULL;
}

// Clear Pending Request
static void arp_pending_clear(const uint8_t ip_address[4])
{
    for (int i = 0; i < ARP_PENDING_SIZE; i++)
    {
        if (!g_arp_pending[i].valid)
        {
            continue;
        }

        if (ip_equal(g_arp_pending[i].ip_address, ip_address))
        {
            g_arp_pending[i].valid = 0;
            return;
        }
    }
}

// Update ARP Cache
static void arp_cache_put(const uint8_t ip_address[4], const uint8_t mac_address[ETHERNET_ADDRESS_SIZE],
    uint32_t current_time_ms)
{
    int slot = -1;

    for (int i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (g_arp_cache[i].valid && ip_equal(g_arp_cache[i].ip_address, ip_address))
        {
            slot = i;
            break;
        }

        if (!g_arp_cache[i].valid && slot < 0)
        {
            slot = i;
        }
    }

    if (slot < 0)
    {
        slot = 0;
    }

    ip_copy(g_arp_cache[slot].ip_address, ip_address);
    mac_copy(g_arp_cache[slot].mac_address, mac_address);
    g_arp_cache[slot].expires_ms = current_time_ms + ARP_CACHE_TTL_MS;
    g_arp_cache[slot].valid = 1;
}

// Lookup ARP Cache
static __attribute__((unused)) int arp_cache_lookup(const uint8_t ip_address[4],
    uint8_t mac_address_out[ETHERNET_ADDRESS_SIZE], uint32_t current_time_ms)
{
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (!g_arp_cache[i].valid)
        {
            continue;
        }

        if (g_arp_cache[i].expires_ms <= current_time_ms)
        {
            g_arp_cache[i].valid = 0;
            continue;
        }

        if (ip_equal(g_arp_cache[i].ip_address, ip_address))
        {
            mac_copy(mac_address_out, g_arp_cache[i].mac_address);
            return 1;
        }
    }

    return 0;
}

// Send ARP Request
static __attribute__((unused)) void arp_send_request(arp_device_t *device_entry,
    const uint8_t target_ip_address[4], uint32_t current_time_ms)
{
    uint8_t request_frame[ETHERNET_HEADER_SIZE + sizeof(arp_packet_t)];
    ethernet_header_t *ethernet_header = (ethernet_header_t *)request_frame;
    arp_packet_t *arp_packet = (arp_packet_t *)(request_frame + ETHERNET_HEADER_SIZE);
    uint8_t broadcast[ETHERNET_ADDRESS_SIZE] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    mac_copy(ethernet_header->destination, broadcast);
    mac_copy(ethernet_header->source, device_entry->mac_address);
    write_be16(ethernet_header->ethertype, ETHERNET_TYPE_ARP);

    write_be16((uint8_t *)&arp_packet->hardware_type, ARP_HTYPE_ETHERNET);
    write_be16((uint8_t *)&arp_packet->protocol_type, ARP_PTYPE_IPV4);
    arp_packet->hardware_length = ETHERNET_ADDRESS_SIZE;
    arp_packet->protocol_length = 4;
    write_be16((uint8_t *)&arp_packet->operation, ARP_OP_REQUEST);

    mac_copy(arp_packet->sender_mac_address, device_entry->mac_address);
    ip_copy(arp_packet->sender_ip_address, device_entry->ip_address);
    ip_copy(arp_packet->target_ip_address, target_ip_address);

    for (int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        arp_packet->target_mac_address[i] = 0;
    }

    device_entry->operations->send_packet(device_entry->device, request_frame,
        (uint16_t)sizeof(request_frame));

    int pending_slot = -1;

    for (int i = 0; i < ARP_PENDING_SIZE; i++)
    {
        if (g_arp_pending[i].valid && ip_equal(g_arp_pending[i].ip_address, target_ip_address))
        {
            pending_slot = i;
            break;
        }

        if (!g_arp_pending[i].valid && pending_slot < 0)
        {
            pending_slot = i;
        }
    }

    if (pending_slot < 0)
    {
        pending_slot = 0;
    }

    ip_copy(g_arp_pending[pending_slot].ip_address, target_ip_address);
    g_arp_pending[pending_slot].last_request_ms = current_time_ms;
    g_arp_pending[pending_slot].valid = 1;
}

// Send ARP Reply
static void arp_send_reply(arp_device_t *device_entry, const uint8_t target_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t target_ip_address[4])
{
    uint8_t reply_frame[ETHERNET_HEADER_SIZE + sizeof(arp_packet_t)];
    ethernet_header_t *ethernet_header = (ethernet_header_t *)reply_frame;
    arp_packet_t *arp_packet = (arp_packet_t *)(reply_frame + ETHERNET_HEADER_SIZE);

    mac_copy(ethernet_header->destination, target_mac);
    mac_copy(ethernet_header->source, device_entry->mac_address);
    write_be16(ethernet_header->ethertype, ETHERNET_TYPE_ARP);

    write_be16((uint8_t *)&arp_packet->hardware_type, ARP_HTYPE_ETHERNET);
    write_be16((uint8_t *)&arp_packet->protocol_type, ARP_PTYPE_IPV4);
    arp_packet->hardware_length = ETHERNET_ADDRESS_SIZE;
    arp_packet->protocol_length = 4;
    write_be16((uint8_t *)&arp_packet->operation, ARP_OP_REPLY);

    mac_copy(arp_packet->sender_mac_address, device_entry->mac_address);
    mac_copy(arp_packet->target_mac_address, target_mac);
    ip_copy(arp_packet->sender_ip_address, device_entry->ip_address);
    ip_copy(arp_packet->target_ip_address, target_ip_address);

    device_entry->operations->send_packet(device_entry->device, reply_frame,
        (uint16_t)sizeof(reply_frame));
}

// Handle ARP Packet
static void arp_handle_packet(arp_device_t *device_entry, const uint8_t *frame, uint16_t frame_length)
{
    if (!frame || frame_length < ETHERNET_HEADER_SIZE + sizeof(arp_packet_t))
    {
        return;
    }

    ethernet_header_t *ethernet_header = (ethernet_header_t *)frame;
    uint16_t ethertype = read_be16(ethernet_header->ethertype);

    if (ethertype != ETHERNET_TYPE_ARP)
    {
        return;
    }

    arp_packet_t *arp_packet = (arp_packet_t *)(frame + ETHERNET_HEADER_SIZE);

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
    uint32_t current_time_ms = kernel->timer_now_ms();

    arp_cache_put(arp_packet->sender_ip_address, arp_packet->sender_mac_address, current_time_ms);
    arp_pending_clear(arp_packet->sender_ip_address);

    if (operation == ARP_OP_REQUEST && !ip_is_zero(device_entry->ip_address) &&
        ip_equal(arp_packet->target_ip_address, device_entry->ip_address))
    {
        arp_send_reply(device_entry, arp_packet->sender_mac_address, arp_packet->sender_ip_address);
    }
}

// Poll RX Queue
static void arp_poll_device(arp_device_t *device_entry)
{
    if (!device_entry || !device_entry->active || !device_entry->operations)
    {
        return;
    }

    if (!device_entry->operations->packets_available || !device_entry->operations->receive_packet)
    {
        return;
    }

    for (;;)
    {
        if (device_entry->operations->packets_available(device_entry->device) <= 0)
        {
            break;
        }

        int bytes_received = device_entry->operations->receive_packet(device_entry->device,
            device_entry->receive_buffer, ETHERNET_FRAME_MAX);

        if (bytes_received <= 0)
        {
            break;
        }

        arp_handle_packet(device_entry, device_entry->receive_buffer, (uint16_t)bytes_received);
    }
}

// IRQSW Worker
static void arp_irqsw_worker(void *context)
{
    arp_device_t *device_entry = (arp_device_t *)context;

    if (!device_entry)
    {
        return;
    }

    arp_poll_device(device_entry);

    device_entry->irqsw_pending = 0;

    if (device_entry->operations->packets_available(device_entry->device) > 0 && kernel->irqsw_queue)
    {
        if (!device_entry->irqsw_pending)
        {
            device_entry->irqsw_pending = 1;
            kernel->irqsw_queue(arp_irqsw_worker, device_entry);
        }
    }
}

// IRQ Handler
static void arp_irq_handler(unsigned irq, void *context)
{
    (void)irq;

    arp_device_t *device_entry = (arp_device_t *)context;

    if (!device_entry || !kernel->irqsw_queue)
    {
        return;
    }

    if (!device_entry->irqsw_pending)
    {
        device_entry->irqsw_pending = 1;
        kernel->irqsw_queue(arp_irqsw_worker, device_entry);
    }
}

// Device Notify
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

        if (!operations || !operations->get_mac || !operations->send_packet ||
           !operations->receive_packet || !operations->packets_available)
        {
            return;
        }

        device_entry->device = device;
        device_entry->operations = operations;
        device_entry->active = 1;
        device_entry->irqsw_pending = 0;
        device_entry->irq_number = device->irq;

        operations->get_mac(device, device_entry->mac_address);
        ip_copy(device_entry->ip_address, g_default_ip);

        if (kernel->irq_register_handler && device_entry->irq_number != 0 && device_entry->irq_number != 0xFF)
        {
            kernel->irq_register_handler(device_entry->irq_number, arp_irq_handler, device_entry);
        }
    }
    else
    {
        arp_device_t *device_entry = arp_find_device(device);

        if (!device_entry)
        {
            return;
        }

        if (kernel->irq_unregister_handler && device_entry->irq_number != 0 && device_entry->irq_number != 0xFF)
        {
            kernel->irq_unregister_handler(device_entry->irq_number, arp_irq_handler, device_entry);
        }

        device_entry->active = 0;
        device_entry->irqsw_pending = 0;
        device_entry->device = NULL;
        device_entry->operations = NULL;
    }
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    for (int i = 0; i < ARP_MAX_DEVICES; i++)
    {
        g_devices[i].active = 0;
        g_devices[i].irqsw_pending = 0;
        g_devices[i].device = NULL;
        g_devices[i].operations = NULL;
        g_devices[i].irq_number = 0;

        for (int j = 0; j < ETHERNET_ADDRESS_SIZE; j++)
        {
            g_devices[i].mac_address[j] = 0;
        }

        for (int j = 0; j < 4; j++)
        {
            g_devices[i].ip_address[j] = 0;
        }
    }

    for (int i = 0; i < ARP_CACHE_SIZE; i++)
    {
        g_arp_cache[i].valid = 0;
        g_arp_cache[i].expires_ms = 0;
    }

    for (int i = 0; i < ARP_PENDING_SIZE; i++)
    {
        g_arp_pending[i].valid = 0;
        g_arp_pending[i].last_request_ms = 0;
    }

    if (kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(arp_device_notify);
    }
}

void ddf_driver_exit(void)
{
    if (kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(arp_device_notify);
    }

    for (int i = 0; i < ARP_MAX_DEVICES; i++)
    {
        if (g_devices[i].active && kernel && kernel->irq_unregister_handler && 
            g_devices[i].irq_number != 0 &&
            g_devices[i].irq_number != 0xFF)
        {
            kernel->irq_unregister_handler(g_devices[i].irq_number, arp_irq_handler, &g_devices[i]);
        }

        g_devices[i].active = 0;
        g_devices[i].irqsw_pending = 0;
        g_devices[i].device = NULL;
        g_devices[i].operations = NULL;
    }
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
