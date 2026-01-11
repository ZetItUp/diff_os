#pragma once

#include "stdint.h"
#include "stddef.h"

struct device;

typedef enum packet_checksum_status
{
    PACKET_CHECKSUM_UNKNOWN = 0,
    PACKET_CHECKSUM_VALID = 1,
    PACKET_CHECKSUM_INVALID = 2
} packet_checksum_status_t;

typedef struct packet_buffer
{
    uint8_t *buffer;          // Start of allocated buffer
    uint8_t *data;            // Start of valid data
    uint32_t capacity;        // Total bytes allocated
    uint32_t length;          // Bytes of valid data
    uint32_t refcount;        // Shared ownership counter
    uint32_t flags;           // PACKET_FLAG_*

    struct device *ingress_device;
    struct device *egress_device;
    uint16_t vlan_tag;
    uint16_t protocol;        // L2 ethernet type or L3 protocol
    uint32_t timestamp_ms;
    packet_checksum_status_t checksum_status;
} packet_buffer_t;

enum
{
    PACKET_FLAG_INGRESS = 1 << 0,
    PACKET_FLAG_EGRESS = 1 << 1
};

packet_buffer_t *packet_buffer_alloc(uint32_t capacity, uint32_t head);

void packet_buffer_retain(packet_buffer_t *packet);

void packet_buffer_release(packet_buffer_t *packet);

static inline uint32_t packet_head(const packet_buffer_t *packet)
{
    if (!packet || !packet->buffer || !packet->data)
    {

        return 0;
    }

    return (uint32_t)(packet->data - packet->buffer);
}

static inline uint32_t packet_tail(const packet_buffer_t *packet)
{
    uint32_t headroom;

    if (!packet)
    {

        return 0;
    }

    headroom = packet_head(packet);
    if (packet->capacity < headroom + packet->length)
    {

        return 0;
    }

    return packet->capacity - headroom - packet->length;
}
