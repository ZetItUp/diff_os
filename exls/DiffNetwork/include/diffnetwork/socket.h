#pragma once

#include <stdint.h>

#define NETWORK_SOCKET_PROTOCOL_ICMP 1
#define NETWORK_SOCKET_MAX_PAYLOAD 512

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

int network_socket_create(uint8_t protocol);
int network_socket_close(int socket_id);
int network_socket_send(int socket_id, const network_socket_send_t *send_info);
int network_socket_recv(int socket_id, network_socket_packet_t *out_packet);
