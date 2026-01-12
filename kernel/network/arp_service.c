#include "network/arp_service.h"
#include "stddef.h"
#include "stdio.h"

static network_arp_resolve_t g_network_arp_resolver = NULL;

int network_arp_register_resolver(network_arp_resolve_t resolver)
{
    if (!resolver)
    {

        puts("[ARP] register resolver null\n");

        return -1;
    }

    g_network_arp_resolver = resolver;

    puts("[ARP] resolver registered\n");

    return 0;
}

int network_arp_resolve(const uint8_t ip_address[4], uint8_t mac_address[6])
{
    if (!g_network_arp_resolver)
    {

        puts("[ARP] resolver missing\n");

        return -1;
    }

    return g_network_arp_resolver(ip_address, mac_address);
}
