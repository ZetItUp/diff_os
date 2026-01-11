#include <diffnetwork/ipv4.h>
#include <diffnetwork/network.h>
#include <syscall.h>

uint8_t ipv4_get_version(const ipv4_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return (uint8_t)(header->version_and_header_length >> 4);
}

uint16_t ipv4_get_header_length(const ipv4_header_t *header)
{
    uint8_t header_word_count;

    if (!header)
    {

        return 0;
    }

    // IHL is number of 32 bit words
    header_word_count = (uint8_t)(header->version_and_header_length & 0x0F);

    return (uint16_t)header_word_count * 4;
}

uint16_t ipv4_get_total_length(const ipv4_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return network_read16((const uint8_t *)&header->total_length);
}

int ipv4_header_is_valid_basic(const ipv4_header_t *header, uint16_t packet_length)
{
    uint16_t header_length;
    uint16_t total_length;

    if (!header)
    {

        return 0;
    }

    if (ipv4_get_version(header) != IPV4_VERSION)
    {

        return 0;
    }

    header_length = ipv4_get_header_length(header);

    if (header_length < IPV4_HEADER_MIN || header_length > packet_length)
    {

        return 0;
    }

    total_length = ipv4_get_total_length(header);

    if (total_length < header_length || total_length > packet_length)
    {

        return 0;
    }

    return 1;
}

uint16_t ipv4_checksum_sum(const uint8_t *data, uint16_t length)
{
    uint32_t sum;
    uint16_t index;

    if (!data)
    {

        return 0;
    }

    sum = 0;
    index = 0;

    // Sum 16 bit words in network order
    while (index + 1 < length)
    {
        sum += (uint32_t)((uint16_t)data[index] << 8 | (uint16_t)data[index + 1]);
        index += 2;
    }

    // Handle odd byte
    if (index < length)
    {
        sum += (uint32_t)((uint16_t)data[index] << 8);
    }

    // Fold carry into 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)sum;
}

int ipv4_checksum_is_valid(const ipv4_header_t *header)
{
    uint16_t header_length;

    if (!header)
    {

        return 0;
    }

    header_length = ipv4_get_header_length(header);

    if (header_length < IPV4_HEADER_MIN)
    {

        return 0;
    }

    // Valid checksum yields all bits set after sum
    return ipv4_checksum_sum((const uint8_t *)header, header_length) == 0xFFFF;
}

int ipv4_get_config(ipv4_config_t *out)
{
    if (!out)
    {

        return -1;
    }

    return do_sys(SYSTEM_IPV4_GET_CONFIG, (int)(uintptr_t)out, 0, 0, 0);
}
