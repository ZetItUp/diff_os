#pragma once

#include <stdint.h>

#define ETHERNET_ADDRESS_SIZE 6 // MAC address length
#define ETHERNET_HEADER_SIZE 14 // Ethernet header size
#define ETHERNET_MTU 1500 // Max payload size

#define ETHERNET_TYPE_IPV4 0x0800 // IPv4 ethertype
#define ETHERNET_TYPE_ARP 0x0806 // ARP ethertype

typedef struct ethernet_header
{
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint16_t ethertype;
} __attribute__((packed)) ethernet_header_t;
