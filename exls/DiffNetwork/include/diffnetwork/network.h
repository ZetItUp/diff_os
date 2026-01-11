#pragma once

#include <stdint.h>
#include <diffnetwork/arp.h>
#include <diffnetwork/ethernet.h>
#include <diffnetwork/icmp.h>
#include <diffnetwork/ipv4.h>

#define NETWORK_IP_ADDRESS_SIZE 4 // IPv4 address size

uint16_t network_read16(const uint8_t *data);
void network_write16(uint8_t *data, uint16_t value);

void network_ip_copy(uint8_t destination_ip[NETWORK_IP_ADDRESS_SIZE],
    const uint8_t source_ip[NETWORK_IP_ADDRESS_SIZE]);
int network_ip_equal(const uint8_t left_ip[NETWORK_IP_ADDRESS_SIZE],
    const uint8_t right_ip[NETWORK_IP_ADDRESS_SIZE]);

void network_mac_copy(uint8_t destination_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t source_mac[ETHERNET_ADDRESS_SIZE]);
int network_mac_equal(const uint8_t left_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t right_mac[ETHERNET_ADDRESS_SIZE]);
