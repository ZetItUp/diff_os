#pragma once

#include <stdint.h>

#define IPV4_VERSION 4 // IPv4 version
#define IPV4_HEADER_MIN 20 // IPv4 header size

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

#define IPV4_DEVICE_NAME_LEN 32 // Device name length

typedef struct ipv4_config
{
    char device_name[IPV4_DEVICE_NAME_LEN];
    uint8_t use_dhcp;
    uint8_t ip_address[4];
    uint8_t netmask[4];
    uint8_t gateway[4];
    uint8_t primary_dns[4];
    uint8_t secondary_dns[4];
    uint16_t mtu;
    uint8_t default_ttl;
    uint8_t valid;
} ipv4_config_t;

uint8_t ipv4_get_version(const ipv4_header_t *header);
uint16_t ipv4_get_header_length(const ipv4_header_t *header);
uint16_t ipv4_get_total_length(const ipv4_header_t *header);
int ipv4_header_is_valid_basic(const ipv4_header_t *header, uint16_t packet_length);
uint16_t ipv4_checksum_sum(const uint8_t *data, uint16_t length);
int ipv4_checksum_is_valid(const ipv4_header_t *header);
int ipv4_get_config(ipv4_config_t *out);
