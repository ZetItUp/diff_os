#include <stdio.h>
#include <stdint.h>
#include <diffnetwork/ipv4.h>

// Print IPv4 address
static void print_ip_value(const char *label, const uint8_t ip_address[4], int valid)
{
    if (!valid)
    {
        printf("%s: n/a\n", label);

        return;
    }

    printf("%s: %u.%u.%u.%u\n", label,
        (unsigned)ip_address[0],
        (unsigned)ip_address[1],
        (unsigned)ip_address[2],
        (unsigned)ip_address[3]);
}

int main(void)
{
    ipv4_config_t config;

    if (ipv4_get_config(&config) != 0)
    {
        printf("iptest: ipv4 config unavailable\n");

        return 1;
    }

    printf("IPv4 test\n");
    printf("Header version: %u\n", (unsigned)IPV4_VERSION);
    printf("Header min size: %u\n", (unsigned)IPV4_HEADER_MIN);

    if (config.device_name[0] != '\0')
    {
        printf("Device: %s\n", config.device_name);
    }
    else
    {
        printf("Device: n/a\n");
    }

    if (config.valid)
    {
        printf("Config: valid\n");
    }
    else
    {
        printf("Config: invalid\n");
    }

    printf("Mode: %s\n", config.use_dhcp ? "dhcp" : "static");

    print_ip_value("IP", config.ip_address, config.valid);
    print_ip_value("Netmask", config.netmask, config.valid);
    print_ip_value("Gateway", config.gateway, config.valid);
    print_ip_value("Primary DNS", config.primary_dns, config.valid);
    print_ip_value("Secondary DNS", config.secondary_dns, config.valid);

    if (config.valid && config.mtu != 0)
    {
        printf("MTU: %u\n", (unsigned)config.mtu);
    }
    else
    {
        printf("MTU: n/a\n");
    }

    if (config.valid && config.default_ttl != 0)
    {
        printf("TTL: %u\n", (unsigned)config.default_ttl);
    }
    else
    {
        printf("TTL: n/a\n");
    }

    return 0;
}
