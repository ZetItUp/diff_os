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
#define IPV4_PROTOCOL_ICMP 1
#define IPV4_MAX_DEVICES 4

#define IPV4_FLAG_MORE_FRAGMENTS 0x2000
#define IPV4_FRAGMENT_MASK 0x1FFF

#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_CODE_ECHO 0

#define ICMP_TRACE 1

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

typedef struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;

typedef struct icmp_device
{
    device_t *device;
    network_device_t *operations;
    network_interface_t *interface;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t ip_address[4];
    uint8_t netmask[4];
    int active;
} icmp_device_t;

static icmp_device_t g_devices[IPV4_MAX_DEVICES];

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

static uint16_t checksum_sum(const uint8_t *data, uint16_t length)
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

static uint16_t checksum_finish(const uint8_t *data, uint16_t length)
{
    return (uint16_t)~checksum_sum(data, length);
}

static int checksum_valid(const uint8_t *data, uint16_t length)
{
    if (!data)
    {
        return 0;
    }

    return checksum_sum(data, length) == 0xFFFF;
}

static icmp_device_t *icmp_find_slot(void)
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

static icmp_device_t *icmp_find_device(device_t *device)
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

static int icmp_device_name_match(const char *device_name)
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

static icmp_device_t *icmp_find_device_for_packet(packet_buffer_t *packet)
{
    if (!packet || !packet->ingress_device)
    {
        return NULL;
    }

    return icmp_find_device(packet->ingress_device);
}

static network_interface_t *icmp_get_interface(icmp_device_t *device_entry)
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

static int icmp_send_frame(icmp_device_t *device_entry, const uint8_t *frame, uint16_t frame_length)
{
    if (!device_entry || !frame || frame_length == 0)
    {
        return -1;
    }

#if ICMP_TRACE
    if (kernel && kernel->printf)
    {
        kernel->printf("[ICMP] send_frame len=%u\n", (unsigned)frame_length);
    }
#endif

    network_interface_t *interface = icmp_get_interface(device_entry);

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
        packet->protocol = ETHERNET_TYPE_IPV4;

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

static void icmp_send_echo_reply(icmp_device_t *device_entry,
    const ethernet_header_t *ethernet_header,
    const ipv4_header_t *ipv4_header,
    const uint8_t *icmp_payload,
    uint16_t icmp_length)
{
    if (!device_entry || !ethernet_header || !ipv4_header || !icmp_payload)
    {
        return;
    }

    if (icmp_length < sizeof(icmp_header_t))
    {
        return;
    }

#if ICMP_TRACE
    if (kernel && kernel->printf)
    {
        kernel->printf("[ICMP] echo_reply len=%u\n", (unsigned)icmp_length);
    }
#endif

    uint8_t frame[ETHERNET_FRAME_MAX];
    uint16_t header_length = IPV4_HEADER_MIN;
    uint16_t ipv4_length = (uint16_t)(header_length + icmp_length);

    if (ipv4_length > ETHERNET_MTU)
    {
        return;
    }

    uint16_t total_length = (uint16_t)(ETHERNET_HEADER_SIZE + ipv4_length);

    ethernet_header_t *reply_ethernet = (ethernet_header_t *)frame;
    ipv4_header_t *reply_ipv4 = (ipv4_header_t *)(frame + ETHERNET_HEADER_SIZE);
    icmp_header_t *reply_icmp = (icmp_header_t *)((uint8_t *)reply_ipv4 + header_length);

    for (int index = 0; index < ETHERNET_ADDRESS_SIZE; index++)
    {
        reply_ethernet->destination[index] = ethernet_header->source[index];
        reply_ethernet->source[index] = device_entry->mac_address[index];
    }

    write_be16(reply_ethernet->ethernet_type, ETHERNET_TYPE_IPV4);

    reply_ipv4->version_and_header_length = (uint8_t)((IPV4_VERSION << 4) | 5);
    reply_ipv4->differentiated_services_and_ecn = 0;
    write_be16((uint8_t *)&reply_ipv4->total_length, ipv4_length);
    write_be16((uint8_t *)&reply_ipv4->identification, 0);
    write_be16((uint8_t *)&reply_ipv4->flags_and_fragment_offset, 0);
    reply_ipv4->time_to_live = 64;
    reply_ipv4->protocol = IPV4_PROTOCOL_ICMP;
    write_be16((uint8_t *)&reply_ipv4->header_checksum, 0);

    for (int index = 0; index < 4; index++)
    {
        reply_ipv4->source_ip_address[index] = device_entry->ip_address[index];
        reply_ipv4->destination_ip_address[index] = ipv4_header->source_ip_address[index];
    }

    write_be16((uint8_t *)&reply_ipv4->header_checksum,
        checksum_finish((const uint8_t *)reply_ipv4, header_length));

    for (uint16_t index = 0; index < icmp_length; index++)
    {
        ((uint8_t *)reply_icmp)[index] = icmp_payload[index];
    }

    reply_icmp->type = ICMP_TYPE_ECHO_REPLY;
    reply_icmp->code = ICMP_CODE_ECHO;
    write_be16((uint8_t *)&reply_icmp->checksum, 0);
    write_be16((uint8_t *)&reply_icmp->checksum,
        checksum_finish((const uint8_t *)reply_icmp, icmp_length));

    icmp_send_frame(device_entry, frame, total_length);
}

static void icmp_handle_packet(icmp_device_t *device_entry, packet_buffer_t *packet)
{
    if (!device_entry || !packet || !packet->data)
    {
        return;
    }

#if ICMP_TRACE
    if (kernel && kernel->printf)
    {
        kernel->printf("[ICMP] rx packet len=%u\n", (unsigned)packet->length);
    }
#endif

    if (packet->length < ETHERNET_HEADER_SIZE + IPV4_HEADER_MIN)
    {
        return;
    }

    ethernet_header_t *ethernet_header = (ethernet_header_t *)packet->data;
    uint16_t ethernet_type = read_be16(ethernet_header->ethernet_type);

    if (ethernet_type != ETHERNET_TYPE_IPV4)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop non-ipv4 type=0x%04x\n", ethernet_type);
        }
#endif
        return;
    }

    const uint8_t *payload = packet->data + ETHERNET_HEADER_SIZE;
    uint16_t payload_length = (uint16_t)(packet->length - ETHERNET_HEADER_SIZE);

    if (payload_length < IPV4_HEADER_MIN)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop short ipv4 payload\n");
        }
#endif
        return;
    }

    ipv4_header_t *ipv4_header = (ipv4_header_t *)payload;
    uint8_t version = (uint8_t)(ipv4_header->version_and_header_length >> 4);
    uint8_t header_word_count = (uint8_t)(ipv4_header->version_and_header_length & 0x0F);
    uint16_t header_length = (uint16_t)header_word_count * 4;

    if (version != IPV4_VERSION)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop bad version %u\n", (unsigned)version);
        }
#endif
        return;
    }

    if (header_length < IPV4_HEADER_MIN || header_length > payload_length)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop bad header len=%u\n", (unsigned)header_length);
        }
#endif
        return;
    }

    if (!checksum_valid(payload, header_length))
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop bad ipv4 checksum\n");
        }
#endif
        return;
    }

    uint16_t total_length = read_be16((const uint8_t *)&ipv4_header->total_length);

    if (total_length < header_length || total_length > payload_length)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop bad total len=%u\n", (unsigned)total_length);
        }
#endif
        return;
    }

    if (ip_is_zero(device_entry->ip_address))
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop ip not set\n");
        }
#endif
        return;
    }

    if (!ip_equal(ipv4_header->destination_ip_address, device_entry->ip_address))
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop dst mismatch\n");
        }
#endif
        return;
    }

    uint16_t flags_and_fragment = read_be16((const uint8_t *)&ipv4_header->flags_and_fragment_offset);

    if ((flags_and_fragment & IPV4_FLAG_MORE_FRAGMENTS) != 0 ||
        (flags_and_fragment & IPV4_FRAGMENT_MASK) != 0)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop fragmented\n");
        }
#endif
        return;
    }

    if (ipv4_header->protocol != IPV4_PROTOCOL_ICMP)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop proto=%u\n", (unsigned)ipv4_header->protocol);
        }
#endif
        return;
    }

    uint16_t icmp_length = (uint16_t)(total_length - header_length);

    if (icmp_length < sizeof(icmp_header_t))
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop short icmp len=%u\n", (unsigned)icmp_length);
        }
#endif
        return;
    }

    if (header_length + icmp_length > payload_length)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop icmp overrun\n");
        }
#endif
        return;
    }

    icmp_header_t *icmp_header = (icmp_header_t *)(payload + header_length);

    if (!checksum_valid((const uint8_t *)icmp_header, icmp_length))
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop bad icmp checksum\n");
        }
#endif
        return;
    }

    if (icmp_header->type == ICMP_TYPE_ECHO_REPLY && icmp_header->code == ICMP_CODE_ECHO)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] echo_reply id=%u seq=%u\n",
                (unsigned)read_be16((const uint8_t *)&icmp_header->identifier),
                (unsigned)read_be16((const uint8_t *)&icmp_header->sequence));
        }
#endif
        uint16_t identifier = read_be16((const uint8_t *)&icmp_header->identifier);
        uint16_t sequence = read_be16((const uint8_t *)&icmp_header->sequence);
        uint16_t payload_length = (uint16_t)(icmp_length - sizeof(icmp_header_t));
        const uint8_t *payload = (const uint8_t *)(icmp_header + 1);

        if (kernel && kernel->network_socket_deliver_icmp_reply)
        {
            kernel->network_socket_deliver_icmp_reply(ipv4_header->source_ip_address,
                identifier,
                sequence,
                payload,
                payload_length);
        }


        return;
    }

    if (icmp_header->type != ICMP_TYPE_ECHO_REQUEST || icmp_header->code != ICMP_CODE_ECHO)
    {
#if ICMP_TRACE
        if (kernel && kernel->printf)
        {
            kernel->printf("[ICMP] drop type=%u code=%u\n",
                (unsigned)icmp_header->type,
                (unsigned)icmp_header->code);
        }
#endif
        return;
    }

#if ICMP_TRACE
    if (kernel && kernel->printf)
    {
        kernel->printf("[ICMP] echo_request id=%u seq=%u\n",
            (unsigned)read_be16((const uint8_t *)&icmp_header->identifier),
            (unsigned)read_be16((const uint8_t *)&icmp_header->sequence));
    }
#endif

    icmp_send_echo_reply(device_entry, ethernet_header, ipv4_header,
        (const uint8_t *)icmp_header, icmp_length);
}

static void icmp_receive(packet_buffer_t *packet, void *context)
{
    (void)context;

    icmp_device_t *device_entry = icmp_find_device_for_packet(packet);

    if (!device_entry)
    {
        return;
    }

    icmp_handle_packet(device_entry, packet);
}

static void icmp_device_notify(device_t *device, int is_added)
{
    if (!device)
    {
        return;
    }

    if (is_added)
    {
        icmp_device_t *device_entry = icmp_find_slot();
        network_device_t *operations = (network_device_t *)device->operations;

        if (!device_entry)
        {
            return;
        }

        if (!icmp_device_name_match(device->name))
        {
            return;
        }

        if (!operations || !operations->get_mac || !operations->send_packet)
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

        if (kernel && kernel->network_interface_get_by_device)
        {
            device_entry->interface = kernel->network_interface_get_by_device(device);
        }
    }
    else
    {
        icmp_device_t *device_entry = icmp_find_device(device);

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
        }
    }

    if (kernel && kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(icmp_device_notify);
    }

    if (kernel && kernel->network_communicator_register_ethernet_type)
    {
        kernel->network_communicator_register_ethernet_type(ETHERNET_TYPE_IPV4, icmp_receive, NULL);
    }
}

void ddf_driver_exit(void)
{
    if (kernel && kernel->network_communicator_unregister_ethernet_type)
    {
        kernel->network_communicator_unregister_ethernet_type(ETHERNET_TYPE_IPV4, icmp_receive, NULL);
    }

    if (kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(icmp_device_notify);
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
