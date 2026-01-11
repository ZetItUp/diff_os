#include "network/packet.h"
#include "heap.h"
#include "string.h"

packet_buffer_t *packet_buffer_alloc(uint32_t capacity, uint32_t head)
{
    if (capacity == 0 || head > capacity)
    {

        return NULL;
    }

    uint32_t total_size = (uint32_t)sizeof(packet_buffer_t) + capacity;
    packet_buffer_t *packet = (packet_buffer_t *)kmalloc(total_size);

    if (!packet)
    {

        return NULL;
    }

    memset(packet, 0, sizeof(*packet));

    uint8_t *buffer = (uint8_t *)(packet + 1);
    packet->buffer = buffer;
    packet->data = buffer + head;
    packet->capacity = capacity;
    packet->length = 0;
    packet->refcount = 1;
    packet->flags = 0;
    packet->ingress_device = NULL;
    packet->egress_device = NULL;
    packet->vlan_tag = 0;
    packet->protocol = 0;
    packet->timestamp_ms = 0;
    packet->checksum_status = PACKET_CHECKSUM_UNKNOWN;

    return packet;
}

void packet_buffer_retain(packet_buffer_t *packet)
{
    if (!packet)
    {

        return;
    }

    packet->refcount++;
}

void packet_buffer_release(packet_buffer_t *packet)
{
    if (!packet)
    {

        return;
    }

    if (packet->refcount > 0)
    {
        packet->refcount--;
    }

    if (packet->refcount == 0)
    {
        kfree(packet);
    }
}
