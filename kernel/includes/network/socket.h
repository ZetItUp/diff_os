#pragma once

#include "stdint.h"

#define NETWORK_SOCKET_PROTOCOL_ICMP 1
#define NETWORK_SOCKET_MAX_PAYLOAD 512
#define NETWORK_SOCKET_MAX_SOCKETS 16
#define NETWORK_SOCKET_QUEUE_LEN 8

typedef struct network_socket_send
{
    uint8_t destination_ip[4];
    uint16_t identifier;
    uint16_t sequence;
    uint16_t payload_length;
    const uint8_t *payload;
} network_socket_send_t;

typedef struct network_socket_packet
{
    uint8_t source_ip[4];
    uint16_t identifier;
    uint16_t sequence;
    uint16_t payload_length;
    uint8_t payload[NETWORK_SOCKET_MAX_PAYLOAD];
} network_socket_packet_t;

typedef struct network_socket_entry
{
    int used;
    int socket_id;
    int owner_pid;
    uint8_t protocol;
    network_socket_packet_t queue[NETWORK_SOCKET_QUEUE_LEN];
    uint8_t head;
    uint8_t tail;
    uint8_t count;
} network_socket_entry_t;

int network_socket_create(uint8_t protocol);

int network_socket_close(int socket_id, int owner_pid);

int network_socket_send(int socket_id, int owner_pid, const network_socket_send_t *send_info);

int network_socket_recv(int socket_id, int owner_pid, network_socket_packet_t *out_packet);

int network_socket_deliver_icmp_reply(const uint8_t source_ip[4],
    uint16_t identifier,
    uint16_t sequence,
    const uint8_t *payload,
    uint16_t payload_length);
