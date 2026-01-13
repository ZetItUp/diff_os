#include "network/socket.h"
#include "network/arp_service.h"
#include "network/network_communicator.h"
#include "network/network_interface.h"
#include "network/packet.h"
#include "drivers/ipv4_config.h"
#include "system/process.h"
#include "system/spinlock.h"
#include "heap.h"
#include "stdio.h"
#include "string.h"
#include "timer.h"

#define ETHERNET_TYPE_IPV4 0x0800
#define ETHERNET_HEADER_SIZE 14
#define IPV4_HEADER_SIZE 20
#define ICMP_HEADER_SIZE 8
#define IPV4_VERSION 4

#define PING_TRACE 1

static network_socket_entry_t g_network_sockets[NETWORK_SOCKET_MAX_SOCKETS];
static spinlock_t g_network_socket_lock;
static int g_network_socket_lock_inited = 0;
static int g_next_socket_id = 1;

static void network_socket_lock_init(void)
{
    if (!g_network_socket_lock_inited)
    {
        spinlock_init(&g_network_socket_lock);
        g_network_socket_lock_inited = 1;
    }
}

static int network_socket_allocate(uint8_t protocol, int owner_pid)
{
    network_socket_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_socket_lock, &flags);

    int socket_id = -1;

    for (int index = 0; index < NETWORK_SOCKET_MAX_SOCKETS; index++)
    {
        if (!g_network_sockets[index].used)
        {
            network_socket_entry_t *entry = &g_network_sockets[index];
            memset(entry, 0, sizeof(*entry));
            entry->used = 1;
            entry->socket_id = g_next_socket_id++;
            entry->owner_pid = owner_pid;
            entry->protocol = protocol;
            socket_id = entry->socket_id;

            break;
        }
    }

    spin_unlock_irqrestore(&g_network_socket_lock, flags);

    return socket_id;
}

static network_socket_entry_t *network_socket_find(int socket_id)
{
    if (socket_id <= 0)
    {

        return NULL;
    }

    for (int index = 0; index < NETWORK_SOCKET_MAX_SOCKETS; index++)
    {
        if (g_network_sockets[index].used && g_network_sockets[index].socket_id == socket_id)
        {

            return &g_network_sockets[index];
        }
    }

    return NULL;
}

int network_socket_create(uint8_t protocol)
{
    process_t *process = process_current();

    if (!process)
    {

        return -1;
    }

    return network_socket_allocate(protocol, process->pid);
}

int network_socket_close(int socket_id, int owner_pid)
{
    network_socket_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_socket_lock, &flags);

    int result = -1;

    for (int index = 0; index < NETWORK_SOCKET_MAX_SOCKETS; index++)
    {
        network_socket_entry_t *entry = &g_network_sockets[index];

        if (entry->used && entry->socket_id == socket_id && entry->owner_pid == owner_pid)
        {
            memset(entry, 0, sizeof(*entry));
            result = 0;

            break;
        }
    }

    spin_unlock_irqrestore(&g_network_socket_lock, flags);

    return result;
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

static void print_ip(const uint8_t ip_address[4])
{
    printf("%u.%u.%u.%u",
        (unsigned)ip_address[0],
        (unsigned)ip_address[1],
        (unsigned)ip_address[2],
        (unsigned)ip_address[3]);
}

static int network_socket_send_icmp(const network_socket_send_t *send_info)
{
    if (!send_info)
    {

        puts("[PING] send_info is null\n");

        return -1;
    }

    ipv4_config_t config;
    if (ipv4_get_config(&config) != 0)
    {

        puts("[PING] ipv4_get_config failed\n");

        return -1;
    }

    if (!config.valid)
    {

        puts("[PING] ipv4 config invalid\n");

        return -1;
    }

    network_interface_t *interface = network_interface_get_primary();
    if (!interface)
    {

        puts("[PING] no primary interface\n");

        return -1;
    }

#if PING_TRACE
    printf("[PING] send id=%u seq=%u dst=",
        (unsigned)send_info->identifier,
        (unsigned)send_info->sequence);
    print_ip(send_info->destination_ip);
    printf("\n");
#endif

    uint8_t target_ip[4];
    int off_net = 0;

    for (int index = 0; index < 4; index++)
    {
        uint8_t mask = config.netmask[index];
        uint8_t source_net = (uint8_t)(config.ip_address[index] & mask);
        uint8_t destination_net = (uint8_t)(send_info->destination_ip[index] & mask);

        if (source_net != destination_net)
        {
            off_net = 1;

            break;
        }
    }

    if (off_net)
    {
        if (ip_is_zero(config.gateway))
        {

            puts("[PING] gateway is zero\n");

            return -1;
        }

        for (int index = 0; index < 4; index++)
        {
            target_ip[index] = config.gateway[index];
        }
    }
    else
    {
        for (int index = 0; index < 4; index++)
        {
            target_ip[index] = send_info->destination_ip[index];
        }
    }

    if (ip_equal(target_ip, send_info->destination_ip) == 0 &&
        ip_equal(config.gateway, target_ip) == 0)
    {

        puts("[PING] target_ip mismatch\n");

        return -1;
    }

#if PING_TRACE
    printf("[PING] route off_net=%d gw=", off_net);
    print_ip(config.gateway);
    printf(" target=");
    print_ip(target_ip);
    printf("\n");
#endif

    if (ip_equal(send_info->destination_ip, config.ip_address))
    {
        network_socket_deliver_icmp_reply(config.ip_address,
            send_info->identifier,
            send_info->sequence,
            send_info->payload,
            send_info->payload_length);

        return 0;
    }

    uint8_t destination_mac[6];
    int arp_ok = 0;

    for (int attempt = 0; attempt < 10; attempt++)
    {
        if (network_arp_resolve(target_ip, destination_mac) == 0)
        {
            arp_ok = 1;

            break;
        }

        sleep_ms(100);
    }

    if (!arp_ok)
    {
        puts("[PING] arp resolve failed\n");

        return -1;
    }

#if PING_TRACE
    printf("[PING] arp ok target=");
    print_ip(target_ip);
    printf(" mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
        destination_mac[0],
        destination_mac[1],
        destination_mac[2],
        destination_mac[3],
        destination_mac[4],
        destination_mac[5]);
#endif

    uint16_t payload_length = send_info->payload_length;

    if (payload_length > NETWORK_SOCKET_MAX_PAYLOAD)
    {

        puts("[PING] payload too large\n");

        return -1;
    }

    uint16_t icmp_total_length = (uint16_t)(ICMP_HEADER_SIZE + payload_length);
    uint16_t ipv4_length = (uint16_t)(IPV4_HEADER_SIZE + icmp_total_length);
    uint16_t total_length = (uint16_t)(ETHERNET_HEADER_SIZE + ipv4_length);

    packet_buffer_t *packet = packet_buffer_alloc(total_length, 0);
    if (!packet)
    {

        puts("[PING] packet alloc failed\n");

        return -1;
    }

    packet->length = total_length;
    packet->protocol = ETHERNET_TYPE_IPV4;

    uint8_t *frame = packet->data;

    for (int index = 0; index < 6; index++)
    {
        frame[index] = destination_mac[index];
        frame[6 + index] = interface->mac_address[index];
    }

    write_be16(frame + 12, ETHERNET_TYPE_IPV4);

    uint8_t *ipv4 = frame + ETHERNET_HEADER_SIZE;
    ipv4[0] = (uint8_t)((IPV4_VERSION << 4) | 5);
    ipv4[1] = 0;
    write_be16(ipv4 + 2, ipv4_length);
    write_be16(ipv4 + 4, 0);
    write_be16(ipv4 + 6, 0);
    ipv4[8] = config.default_ttl ? config.default_ttl : 64;
    ipv4[9] = 1;
    write_be16(ipv4 + 10, 0);

    for (int index = 0; index < 4; index++)
    {
        ipv4[12 + index] = config.ip_address[index];
        ipv4[16 + index] = send_info->destination_ip[index];
    }

    write_be16(ipv4 + 10, checksum_finish(ipv4, IPV4_HEADER_SIZE));

    uint8_t *icmp = ipv4 + IPV4_HEADER_SIZE;
    icmp[0] = 8;
    icmp[1] = 0;
    write_be16(icmp + 2, 0);
    write_be16(icmp + 4, send_info->identifier);
    write_be16(icmp + 6, send_info->sequence);

    if (payload_length > 0 && send_info->payload)
    {
        memcpy(icmp + ICMP_HEADER_SIZE, send_info->payload, payload_length);
    }

    write_be16(icmp + 2, checksum_finish(icmp, icmp_total_length));

    int result = network_communicator_transmit(interface, packet);

    packet_buffer_release(packet);

#if PING_TRACE
    printf("[PING] tx result=%d\n", result);
#endif

    if (result != 0)
    {
        printf("[PING] transmit failed %d\n", result);

        return -1;
    }

    return result;
}

int network_socket_send(int socket_id, int owner_pid, const network_socket_send_t *send_info)
{
    if (!send_info)
    {

        return -1;
    }

    network_socket_entry_t *entry = network_socket_find(socket_id);

    if (!entry || entry->owner_pid != owner_pid)
    {

        return -1;
    }

    if (entry->protocol == NETWORK_SOCKET_PROTOCOL_ICMP)
    {

        return network_socket_send_icmp(send_info);
    }


    return -1;
}

int network_socket_recv(int socket_id, int owner_pid, network_socket_packet_t *out_packet)
{
    if (!out_packet)
    {

        return -1;
    }

    network_socket_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_socket_lock, &flags);

    network_socket_entry_t *entry = network_socket_find(socket_id);

    if (!entry || entry->owner_pid != owner_pid)
    {
        spin_unlock_irqrestore(&g_network_socket_lock, flags);

        return -1;
    }

    if (entry->count == 0)
    {
        spin_unlock_irqrestore(&g_network_socket_lock, flags);

        return -1;
    }

    *out_packet = entry->queue[entry->head];
    entry->head = (uint8_t)((entry->head + 1) % NETWORK_SOCKET_QUEUE_LEN);
    entry->count--;

    spin_unlock_irqrestore(&g_network_socket_lock, flags);

    return 0;
}

int network_socket_deliver_icmp_reply(const uint8_t source_ip[4],
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    uint16_t payload_length)
{
    if (!source_ip || (payload_length > 0 && !payload))
    {

        return -1;
    }

    if (payload_length > NETWORK_SOCKET_MAX_PAYLOAD)
    {
        payload_length = NETWORK_SOCKET_MAX_PAYLOAD;
    }

    network_socket_lock_init();

    uint32_t flags = 0;
    spin_lock_irqsave(&g_network_socket_lock, &flags);

    for (int index = 0; index < NETWORK_SOCKET_MAX_SOCKETS; index++)
    {
        network_socket_entry_t *entry = &g_network_sockets[index];

        if (!entry->used || entry->protocol != NETWORK_SOCKET_PROTOCOL_ICMP)
        {
            continue;
        }

        if (entry->count >= NETWORK_SOCKET_QUEUE_LEN)
        {
            continue;
        }

        network_socket_packet_t *slot = &entry->queue[entry->tail];

        for (int copy_index = 0; copy_index < 4; copy_index++)
        {
            slot->source_ip[copy_index] = source_ip[copy_index];
        }

        slot->identifier = identifier;
        slot->sequence = sequence;
        slot->payload_length = payload_length;

        for (uint16_t copy_index = 0; copy_index < payload_length; copy_index++)
        {
            slot->payload[copy_index] = payload[copy_index];
        }

        entry->tail = (uint8_t)((entry->tail + 1) % NETWORK_SOCKET_QUEUE_LEN);
        entry->count++;
    }

    spin_unlock_irqrestore(&g_network_socket_lock, flags);

    return 0;
}
