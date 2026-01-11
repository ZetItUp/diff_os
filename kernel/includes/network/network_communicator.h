#pragma once

#include "network/packet.h"
#include "network/network_interface.h"

typedef void (*network_communicator_handler_t)(packet_buffer_t *packet, void *context);

int network_communicator_register_ethernet_type(uint16_t ethernet_type,
    network_communicator_handler_t handler,
    void *context);

int network_communicator_unregister_ethernet_type(uint16_t ethernet_type,
    network_communicator_handler_t handler,
    void *context);

int network_communicator_receive(network_interface_t *interface, packet_buffer_t *packet);

int network_communicator_transmit(network_interface_t *interface, packet_buffer_t *packet);
