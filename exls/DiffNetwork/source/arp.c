#include <diffnetwork/arp.h>
#include <diffnetwork/network.h>

int arp_packet_is_ethernet_ipv4(const arp_packet_t *packet)
{
    if (!packet)
    {

        return 0;
    }

    if (network_read16((const uint8_t *)&packet->hardware_type) != ARP_HARDWARE_TYPE_ETHERNET)
    {

        return 0;
    }

    if (network_read16((const uint8_t *)&packet->protocol_type) != ARP_PROTOCOL_TYPE_IPV4)
    {

        return 0;
    }

    if (packet->hardware_length != ARP_HARDWARE_ADDRESS_LENGTH)
    {

        return 0;
    }

    if (packet->protocol_length != ARP_PROTOCOL_ADDRESS_LENGTH)
    {

        return 0;
    }

    return 1;
}

uint16_t arp_packet_get_operation(const arp_packet_t *packet)
{
    if (!packet)
    {

        return 0;
    }

    return network_read16((const uint8_t *)&packet->operation);
}

int arp_packet_is_request(const arp_packet_t *packet)
{
    if (!packet)
    {

        return 0;
    }

    if (!arp_packet_is_ethernet_ipv4(packet))
    {

        return 0;
    }

    return arp_packet_get_operation(packet) == ARP_OPERATION_REQUEST;
}

int arp_packet_is_reply(const arp_packet_t *packet)
{
    if (!packet)
    {

        return 0;
    }

    if (!arp_packet_is_ethernet_ipv4(packet))
    {

        return 0;
    }

    return arp_packet_get_operation(packet) == ARP_OPERATION_REPLY;
}
