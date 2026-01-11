#include <diffnetwork/icmp.h>

uint8_t icmp_get_type(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->type;
}

uint8_t icmp_get_code(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->code;
}

uint16_t icmp_get_identifier(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->identifier;
}

uint16_t icmp_get_sequence(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->sequence;
}

int icmp_is_echo_request(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->type == ICMP_TYPE_ECHO_REQUEST && header->code == ICMP_CODE_ECHO;
}

int icmp_is_echo_reply(const icmp_header_t *header)
{
    if (!header)
    {

        return 0;
    }

    return header->type == ICMP_TYPE_ECHO_REPLY && header->code == ICMP_CODE_ECHO;
}

int icmp_has_min_length(uint16_t packet_length)
{
    if (packet_length < sizeof(icmp_header_t))
    {

        return 0;
    }

    return 1;
}

// Compute checksum
uint16_t icmp_checksum(const uint8_t *data, uint16_t length)
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


    return (uint16_t)~sum;
}

int icmp_fill_echo_request(uint8_t *packet, uint16_t packet_length,
    uint16_t identifier, uint16_t sequence)
{
    icmp_header_t *header;

    if (!packet)
    {

        return -1;
    }

    if (packet_length < sizeof(icmp_header_t))
    {

        return -1;
    }

    header = (icmp_header_t *)packet;
    header->type = ICMP_TYPE_ECHO_REQUEST;
    header->code = ICMP_CODE_ECHO;
    header->checksum = 0;
    header->identifier = identifier;
    header->sequence = sequence;
    header->checksum = icmp_checksum(packet, packet_length);

    return 0;
}
