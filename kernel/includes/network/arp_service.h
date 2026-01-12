#pragma once

#include "stdint.h"

typedef int (*network_arp_resolve_t)(const uint8_t ip_address[4], uint8_t mac_address[6]);

int network_arp_register_resolver(network_arp_resolve_t resolver);

int network_arp_resolve(const uint8_t ip_address[4], uint8_t mac_address[6]);
