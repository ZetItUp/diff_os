#include "drivers/ddf.h"
#include "drivers/device.h"
#include "drivers/ipv4_config.h"
#include "network/network_communicator.h"
#include "network/network_interface.h"
#include "network/packet.h"
#include "stdint.h"
#include "stddef.h"

#define ETHERNET_ADDRESS_SIZE 6
#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_MTU 1500
#define ETHERNET_FRAME_MAX (ETHERNET_HEADER_SIZE + ETHERNET_MTU)

#define ETHERNET_TYPE_IPV4 0x0800

#define IPV4_VERSION 4
#define IPV4_HEADER_MIN 20
#define IPV4_MAX_DEVICES 4

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static kernel_exports_t *kernel = NULL;
static ipv4_config_t g_ipv4_config;

typedef struct ethernet_header
{
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint8_t ethernet_type[2];
} __attribute__((packed)) ethernet_header_t;

typedef struct ipv4_header
{
    uint8_t version_and_header_length;
    uint8_t differentiated_services_and_ecn;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_and_fragment_offset;
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint8_t source_ip_address[4];
    uint8_t destination_ip_address[4];
} __attribute__((packed)) ipv4_header_t;

typedef struct ipv4_device
{
    device_t *device;
    network_device_t *operations;
    network_interface_t *interface;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t ip_address[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    int active;
} ipv4_device_t;

static ipv4_device_t g_devices[IPV4_MAX_DEVICES];

static uint16_t read_be16(const uint8_t *data)
{
    if (!data)
    {
        return 0;
    }

    return (uint16_t)((uint16_t)data[0] << 8 | (uint16_t)data[1]);
}

static int string_equal(const char *left_text, const char *right_text)
{
    if (!left_text || !right_text)
    {
        return 0;
    }

    while (*left_text && *right_text)
    {
        if (*left_text != *right_text)
        {
            return 0;
        }

        left_text++;
        right_text++;
    }

    return *left_text == '\0' && *right_text == '\0';
}

static void ip_copy(uint8_t output_ip[4], const uint8_t input_ip[4])
{
    for (int index = 0; index < 4; index++)
    {
        output_ip[index] = input_ip[index];
    }
}

static int ip_is_zero(const uint8_t ip_address[4])
{
    for (int index = 0; index < 4; index++)
    {
        if (ip_address[index] != 0)
        {
            return 0;
        }
    }

    return 1;
}

static int ip_equal(const uint8_t left_ip[4], const uint8_t right_ip[4])
{
    if (!left_ip || !right_ip)
    {
        return 0;
    }

    for (int index = 0; index < 4; index++)
    {
        if (left_ip[index] != right_ip[index])
        {
            return 0;
        }
    }

    return 1;
}

static int ip_is_broadcast(const uint8_t device_ip[4], const uint8_t device_netmask[4],
    const uint8_t destination_ip[4])
{
    uint8_t broadcast_address[4];

    if (!device_ip || !device_netmask || !destination_ip)
    {
        return 0;
    }

    for (int index = 0; index < 4; index++)
    {
        broadcast_address[index] = (uint8_t)(device_ip[index] | (uint8_t)~device_netmask[index]);
    }

    if (ip_equal(destination_ip, broadcast_address))
    {
        return 1;
    }

    if (destination_ip[0] == 255 && destination_ip[1] == 255 &&
        destination_ip[2] == 255 && destination_ip[3] == 255)
    {
        return 1;
    }

    return 0;
}

static uint16_t ipv4_checksum_sum(const uint8_t *data, uint16_t length)
{
    uint32_t sum;
    uint16_t index;

    if (!data)
    {
        return 0;
    }

    sum = 0;
    index = 0;

    while (index + 1 < length)
    {
        sum += (uint32_t)((uint16_t)data[index] << 8 | (uint16_t)data[index + 1]);
        index += 2;
    }

    if (index < length)
    {
        sum += (uint32_t)((uint16_t)data[index] << 8);
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)sum;
}

static int ipv4_checksum_valid(const uint8_t *data, uint16_t length)
{
    if (!data)
    {
        return 0;
    }

    return ipv4_checksum_sum(data, length) == 0xFFFF;
}

static ipv4_device_t *ipv4_find_slot(void)
{
    for (int index = 0; index < IPV4_MAX_DEVICES; index++)
    {
        if (!g_devices[index].active)
        {
            return &g_devices[index];
        }
    }

    return NULL;
}

static ipv4_device_t *ipv4_find_device(device_t *device)
{
    if (!device)
    {
        return NULL;
    }

    for (int index = 0; index < IPV4_MAX_DEVICES; index++)
    {
        if (g_devices[index].active && g_devices[index].device == device)
        {
            return &g_devices[index];
        }
    }

    return NULL;
}

static int ipv4_device_name_match(const char *device_name)
{
    if (!device_name)
    {
        return 0;
    }

    if (g_ipv4_config.device_name[0] == '\0')
    {
        return 1;
    }

    return string_equal(device_name, g_ipv4_config.device_name);
}

static ipv4_device_t *ipv4_find_device_for_packet(packet_buffer_t *packet)
{
    if (!packet || !packet->ingress_device)
    {
        return NULL;
    }

    return ipv4_find_device(packet->ingress_device);
}

static void ipv4_handle_packet(ipv4_device_t *device_entry, packet_buffer_t *packet)
{
    if (!device_entry || !packet || !packet->data)
    {
        return;
    }

    if (packet->length < ETHERNET_HEADER_SIZE + IPV4_HEADER_MIN)
    {
        return;
    }

    ethernet_header_t *ethernet_header = (ethernet_header_t *)packet->data;
    uint16_t ethernet_type = read_be16(ethernet_header->ethernet_type);

    if (ethernet_type != ETHERNET_TYPE_IPV4)
    {
        return;
    }

    const uint8_t *payload = packet->data + ETHERNET_HEADER_SIZE;
    uint16_t payload_length = (uint16_t)(packet->length - ETHERNET_HEADER_SIZE);

    if (payload_length < IPV4_HEADER_MIN)
    {
        return;
    }

    ipv4_header_t *header = (ipv4_header_t *)payload;
    uint8_t version = (uint8_t)(header->version_and_header_length >> 4);
    uint8_t header_word_count = (uint8_t)(header->version_and_header_length & 0x0F);
    uint16_t header_length = (uint16_t)header_word_count * 4;

    if (version != IPV4_VERSION)
    {
        return;
    }

    if (header_length < IPV4_HEADER_MIN || header_length > payload_length)
    {
        return;
    }

    if (!ipv4_checksum_valid(payload, header_length))
    {
        return;
    }

    uint16_t total_length = read_be16((const uint8_t *)&header->total_length);

    if (total_length < header_length || total_length > payload_length)
    {
        return;
    }

    if (ip_is_zero(device_entry->ip_address))
    {
        return;
    }

    if (!ip_equal(header->destination_ip_address, device_entry->ip_address) &&
        !ip_is_broadcast(device_entry->ip_address, device_entry->netmask, header->destination_ip_address))
    {
        return;
    }
}

static void ipv4_receive(packet_buffer_t *packet, void *context)
{
    (void)context;

    ipv4_device_t *device_entry = ipv4_find_device_for_packet(packet);

    if (!device_entry)
    {
        return;
    }

    ipv4_handle_packet(device_entry, packet);
}

static void ipv4_device_notify(device_t *device, int is_added)
{
    if (!device)
    {
        return;
    }

    if (is_added)
    {
        ipv4_device_t *device_entry = ipv4_find_slot();
        network_device_t *operations = (network_device_t *)device->operations;

        if (!device_entry)
        {
            return;
        }

        if (!ipv4_device_name_match(device->name))
        {
            return;
        }

        if (!operations || !operations->get_mac)
        {
            return;
        }

        device_entry->device = device;
        device_entry->operations = operations;
        device_entry->interface = NULL;
        device_entry->active = 1;

        operations->get_mac(device, device_entry->mac_address);
        ip_copy(device_entry->ip_address, g_ipv4_config.ip_address);
        ip_copy(device_entry->netmask, g_ipv4_config.netmask);
        ip_copy(device_entry->gateway, g_ipv4_config.gateway);

        if (kernel && kernel->network_interface_get_by_device)
        {
            device_entry->interface = kernel->network_interface_get_by_device(device);
        }
    }
    else
    {
        ipv4_device_t *device_entry = ipv4_find_device(device);

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

    for (int index = 0; index < DEVICE_NAME_LEN; index++)
    {
        g_ipv4_config.device_name[index] = '\0';
    }

    for (int index = 0; index < 4; index++)
    {
        g_ipv4_config.ip_address[index] = 0;
        g_ipv4_config.netmask[index] = 0;
        g_ipv4_config.gateway[index] = 0;
        g_ipv4_config.primary_dns[index] = 0;
        g_ipv4_config.secondary_dns[index] = 0;
    }

    g_ipv4_config.use_dhcp = 0;
    g_ipv4_config.mtu = 0;
    g_ipv4_config.default_ttl = 0;
    g_ipv4_config.valid = 0;

    if (kernel && kernel->ipv4_get_config)
    {
        kernel->ipv4_get_config(&g_ipv4_config);
    }

    for (int index = 0; index < IPV4_MAX_DEVICES; index++)
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
            g_devices[index].netmask[ip_index] = 0;
            g_devices[index].gateway[ip_index] = 0;
        }
    }

    if (kernel && kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(ipv4_device_notify);
    }

    if (kernel && kernel->network_communicator_register_ethernet_type)
    {
        kernel->network_communicator_register_ethernet_type(ETHERNET_TYPE_IPV4, ipv4_receive, NULL);
    }
}

void ddf_driver_exit(void)
{
    if (kernel && kernel->network_communicator_unregister_ethernet_type)
    {
        kernel->network_communicator_unregister_ethernet_type(ETHERNET_TYPE_IPV4, ipv4_receive, NULL);
    }

    if (kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(ipv4_device_notify);
    }

    for (int index = 0; index < IPV4_MAX_DEVICES; index++)
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
