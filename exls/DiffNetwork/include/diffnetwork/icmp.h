#pragma once

#include <stdint.h>

#define ICMP_TYPE_ECHO_REPLY 0 // Echo reply type
#define ICMP_TYPE_ECHO_REQUEST 8 // Echo request type
#define ICMP_CODE_ECHO 0 // Echo code

typedef struct icmp_header
{
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed)) icmp_header_t;

uint8_t icmp_get_type(const icmp_header_t *header);
uint8_t icmp_get_code(const icmp_header_t *header);
uint16_t icmp_get_identifier(const icmp_header_t *header);
uint16_t icmp_get_sequence(const icmp_header_t *header);
int icmp_is_echo_request(const icmp_header_t *header);
int icmp_is_echo_reply(const icmp_header_t *header);
int icmp_has_min_length(uint16_t packet_length);
uint16_t icmp_checksum(const uint8_t *data, uint16_t length);
int icmp_fill_echo_request(uint8_t *packet, uint16_t packet_length,
    uint16_t identifier, uint16_t sequence);
