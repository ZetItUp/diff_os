#pragma once

#include <stdint.h>
#include <diffnetwork/ethernet.h>

#define ARP_HARDWARE_TYPE_ETHERNET 1 // Ethernet hardware type
#define ARP_PROTOCOL_TYPE_IPV4 0x0800 // IPv4 protocol type

#define ARP_OPERATION_REQUEST 1 // ARP request operation
#define ARP_OPERATION_REPLY 2 // ARP reply operation

#define ARP_HARDWARE_ADDRESS_LENGTH 6 // Hardware address size
#define ARP_PROTOCOL_ADDRESS_LENGTH 4 // Protocol address size

typedef struct arp_packet
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t hardware_length;
    uint8_t protocol_length;
    uint16_t operation;
    uint8_t sender_mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t sender_ip_address[ARP_PROTOCOL_ADDRESS_LENGTH];
    uint8_t target_mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t target_ip_address[ARP_PROTOCOL_ADDRESS_LENGTH];
} __attribute__((packed)) arp_packet_t;

int arp_packet_is_ethernet_ipv4(const arp_packet_t *packet);
uint16_t arp_packet_get_operation(const arp_packet_t *packet);
int arp_packet_is_request(const arp_packet_t *packet);
int arp_packet_is_reply(const arp_packet_t *packet);
