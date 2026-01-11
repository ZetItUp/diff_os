#pragma once

#include "diff.h"
#include "drivers/device.h"
#include "stdint.h"

typedef struct ipv4_config
{
    char device_name[DEVICE_NAME_LEN];
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

int ipv4_config_load(const FileTable *table, const char *path);
int ipv4_get_config(ipv4_config_t *out);
