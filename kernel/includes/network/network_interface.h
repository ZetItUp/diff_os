#pragma once

#include "stdint.h"
#include "network/packet.h"

struct device;

typedef struct network_interface network_interface_t;

typedef struct network_interface_ops
{
    int (*transmit)(network_interface_t *interface, packet_buffer_t *packet);
    int (*set_promiscuous)(network_interface_t *interface, int enabled);
    int (*set_multicast)(network_interface_t *interface, int enabled);
    int (*get_link_status)(network_interface_t *interface);
    uint32_t (*get_speed)(network_interface_t *interface);
} network_interface_ops_t;

struct network_interface
{
    struct device *device;
    network_interface_ops_t *ops;
    uint8_t mac_address[6];
    uint32_t mtu;
    void *private_data;
};

network_interface_t *network_interface_register(struct device *device,
    network_interface_ops_t *ops,
    const uint8_t mac_address[6],
    uint32_t mtu,
    void *private_data);

void network_interface_unregister(network_interface_t *interface);

network_interface_t *network_interface_get_primary(void);

network_interface_t *network_interface_get_by_device(struct device *device);

int network_interface_receive(network_interface_t *interface, packet_buffer_t *packet);
