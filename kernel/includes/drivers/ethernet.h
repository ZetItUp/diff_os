#pragma once

#include "drivers/device.h"
#include "stdint.h"

#define ETHERNET_ADDRESS_SIZE   6
#define ETHERNET_HEADER_SIZE    14
#define ETHERNET_MTU            1500

#define ETHERNET_TYPE_IPV4      0x0800
#define ETHERNET_TYPE_ARP       0x0806

// Ethernet RX handler
typedef void (*ethernet_rx_handler_t)(const uint8_t *payload,
                                      uint16_t payload_length,
                                      uint16_t ethernet_type,
                                      const uint8_t source[ETHERNET_ADDRESS_SIZE],
                                      const uint8_t destination[ETHERNET_ADDRESS_SIZE],
                                      void *context);

int ethernet_register_handler(uint16_t ethernet_type, ethernet_rx_handler_t handler, void *context);
int ethernet_unregister_handler(uint16_t ethernet_type, ethernet_rx_handler_t handler);
void ethernet_poll(void);
device_t *ethernet_get_primary_device(void);
int ethernet_send(device_t *device, const uint8_t destination[ETHERNET_ADDRESS_SIZE], 
                  uint16_t ethernet_type,
                  const void *payload, 
                  uint16_t payload_length);
