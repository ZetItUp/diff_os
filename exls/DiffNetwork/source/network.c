#include <diffnetwork/network.h>

uint16_t network_read16(const uint8_t *data)
{
    if (!data)
    {
        return 0;
    }

    return (uint16_t)((uint16_t)data[0] << 8 | (uint16_t)data[1]);
}

void network_write16(uint8_t *data, uint16_t value)
{
    if (!data)
    {
        return;
    }

    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

void network_ip_copy(uint8_t destination_ip[NETWORK_IP_ADDRESS_SIZE],
    const uint8_t source_ip[NETWORK_IP_ADDRESS_SIZE])
{
    for (int i = 0; i < NETWORK_IP_ADDRESS_SIZE; i++)
    {
        destination_ip[i] = source_ip[i];
    }
}

int network_ip_equal(const uint8_t left_ip[NETWORK_IP_ADDRESS_SIZE],
    const uint8_t right_ip[NETWORK_IP_ADDRESS_SIZE])
{
    if (!left_ip || !right_ip)
    {
        return 0;
    }

    for (int i = 0; i < NETWORK_IP_ADDRESS_SIZE; i++)
    {
        if (left_ip[i] != right_ip[i])
        {
            return 0;
        }
    }

    return 1;
}

void network_mac_copy(uint8_t destination_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t source_mac[ETHERNET_ADDRESS_SIZE])
{
    for (int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        destination_mac[i] = source_mac[i];
    }
}

int network_mac_equal(const uint8_t left_mac[ETHERNET_ADDRESS_SIZE],
    const uint8_t right_mac[ETHERNET_ADDRESS_SIZE])
{
    if (!left_mac || !right_mac)
    {
        return 0;
    }

    for (int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        if (left_mac[i] != right_mac[i])
        {
            return 0;
        }
    }

    return 1;
}
