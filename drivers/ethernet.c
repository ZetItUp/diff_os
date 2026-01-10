#include "drivers/ddf.h"
#include "drivers/device.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"

#define ETHERNET_ADDRESS_SIZE   6
#define ETHERNET_HEADER_SIZE    14
#define ETHERNET_MTU            1500        // Maximum Transmission Unit
#define ETHERNET_FRAME_MAX      (ETHERNET_HEADER_SIZE + ETHERNET_MTU)
#define ETHERNET_MAX_HANDLERS   8
#define ETHERNET_MAX_DEVICES    4

#define ETHERNET_TYPE_IPV4      0x0800
#define ETHERNET_TYPE_ARP       0x0806

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static volatile kernel_exports_t *kernel = 0;

// Ethernet Header
typedef struct ethernet_header
{
    uint8_t destination[ETHERNET_ADDRESS_SIZE];
    uint8_t source[ETHERNET_ADDRESS_SIZE];
    uint8_t type[2];
} __attribute__((packed)) ethernet_header_t;

// Ethernet RX Handler
typedef void (*ethernet_rx_handler_t)(const uint8_t *payload,
                                      uint16_t payload_length,
                                      uint16_t ethernet_type,
                                      const uint8_t source[ETHERNET_ADDRESS_SIZE],
                                      const uint8_t destination[ETHERNET_ADDRESS_SIZE],
                                      void *context);

// Ethernet Handler
typedef struct ethernet_handler
{
    uint16_t ethernet_type;
    ethernet_rx_handler_t handler;
    void *context;
} ethernet_handler_t;

// Ethernet Device
typedef struct ethernet_device
{
    device_t *device;
    network_device_t *operations;
    uint8_t mac_address[ETHERNET_ADDRESS_SIZE];
    uint8_t receive_buffer[ETHERNET_FRAME_MAX];
    int active;
} ethernet_device_t;

// Global Handlers
static ethernet_handler_t g_handlers[ETHERNET_MAX_HANDLERS];
static int g_handler_count = 0;
static ethernet_device_t g_devices[ETHERNET_MAX_DEVICES];


// Helpers

// Read Data With Big Endian 16-bits
static uint16_t read_be16(const uint8_t *data)
{
    if(!data)
    {
        return 0;
    }

    return (uint16_t)((uint16_t)data[0] << 8 | (uint16_t)data[1]);
}

// Write Data With Big Endian 16-bits
static void write_be16(uint8_t *data, uint16_t value)
{
    if(!data)
    {
        return;
    }

    data[0] = (uint8_t)(value >> 8);
    data[1] = (uint8_t)(value & 0xFF);
}

// Register Ethernet Handler
int ethernet_register_handler(uint16_t ethernet_type, ethernet_rx_handler_t handler, void *context)
{
    if(!handler)
    {
        return -1;
    }

    for(int i = 0; i < g_handler_count; i++)
    {
        if(g_handlers[i].ethernet_type == ethernet_type && g_handlers[i].handler == handler)
        {
            return 0;
        }
    }

    if(g_handler_count >= ETHERNET_MAX_HANDLERS)
    {
        return -1;
    }

    g_handlers[g_handler_count].ethernet_type = ethernet_type;
    g_handlers[g_handler_count].handler = handler;
    g_handlers[g_handler_count].context = context;
    g_handler_count++;

    return 0;
}

// Unregister Ethernet Handler
int ethernet_unregister_handler(uint16_t ethernet_type, ethernet_rx_handler_t handler)
{
    if(!handler)
    {
        return -1;
    }   

    for(int i = 0; i < g_handler_count; i++)
    {
        if(g_handlers[i].ethernet_type == ethernet_type && g_handlers[i].handler == handler)
        {
            for(int j; j < g_handler_count - 1; j++)
            {
                g_handlers[j] = g_handlers[j + 1];
            }

            g_handler_count--;

            return 0;
        }   
    }

    return -1;
}

// Ethernet Dispatch
static void ethernet_dispatch(const uint8_t *frame, uint16_t frame_length)
{
    if(!frame || frame_length < ETHERNET_HEADER_SIZE)
    {
        return;
    }

    // Get Ethernet Type
    const ethernet_header_t *header = (const ethernet_header_t*)frame;
    uint16_t ethernet_type = read_be16(header->type);

    // Get Payload and Length
    const uint8_t *payload = frame + ETHERNET_HEADER_SIZE;
    uint16_t payload_length = (uint16_t)(frame_length - ETHERNET_HEADER_SIZE);

    // Find the correct handler and handle the payload
    for(int i = 0; i < g_handler_count; i++)
    {
        if(g_handlers[i].ethernet_type == ethernet_type && g_handlers[i].handler)
        {
            g_handlers[i].handler(payload, payload_length, ethernet_type, header->source, header->destination, g_handlers[i].context);
        }
    }
}

// Poll Ethernet Device
static void ethernet_poll_device(ethernet_device_t *entry)
{
    if(!entry || !entry->active || !entry->operations)
    {
        return;
    }

    // Make sure we have packets available
    if(!entry->operations->packets_available || !entry->operations->receive_packet)
    {
        return;
    }

    while(entry->operations->packets_available(entry->device) > 0)
    {
        // Attempt to receive packet
        int received = entry->operations->receive_packet(entry->device, entry->receive_buffer, ETHERNET_FRAME_MAX);

        if(received <= 0)
        {
            // No packet data received
            break;
        }

        ethernet_dispatch(entry->receive_buffer, (uint16_t)received);
    }
}

// Poll All Ethernet Devices
void ethernet_poll(void)
{
    for(int i = 0; i< ETHERNET_MAX_DEVICES; i++)
    {
        if(g_devices[i].active)
        {
            ethernet_poll_device(&g_devices[i]);
        }
    }
}

// Find Free Device Slot
static ethernet_device_t *ethernet_find_slot(void)
{
    for(int i = 0; i < ETHERNET_MAX_DEVICES; i++)
    {
        if(!g_devices[i].active)
        {
            return &g_devices[i];
        }
    }

    return NULL;
}

// Find Ethernet Device
static ethernet_device_t *ethernet_find_device(device_t *device)
{
    if(!device)
    {
        return NULL;
    }

    for(int i = 0; i < ETHERNET_MAX_DEVICES; i++)
    {
        if(g_devices[i].active && g_devices[i].device == device)
        {
            return &g_devices[i];
        }
    }

    return NULL;
}

// Notify Ethernet Device
static void ethernet_device_notify(device_t *device, int added)
{
    if(!device)
    {
        return;
    }

    if(added)
    {
        ethernet_device_t *entry = ethernet_find_slot();

        if(!entry)
        {
            return;
        }

        network_device_t *operations = (network_device_t*)device->operations;

        if(!operations || !operations->get_mac)
        {
            return;
        }

        entry->device = device;
        entry->operations = operations;
        entry->active = 1;

        operations->get_mac(device, entry->mac_address);
    }
    else 
    {
        ethernet_device_t *entry = ethernet_find_device(device);

        if(!entry)
        {
            return;
        }

        entry->active = 0;
        entry->device = NULL;
        entry->operations = NULL;

        for(int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
        {
            entry->mac_address[i] = 0;
        }   
    }
}

// Get Primary Device
device_t *ethernet_get_primary_device(void)
{
    for(int i = 0; i < ETHERNET_MAX_DEVICES; i++)
    {
        if(!g_devices[i].active)
        {
            return g_devices[i].device;
        }
    }

    return NULL;
}

// Send Payload
int ethernet_send(device_t *device, const uint8_t destination[ETHERNET_ADDRESS_SIZE], uint16_t ethernet_type,
                  const void *payload, uint16_t payload_length)
{
    if(!device || !destination || !payload)
    {
        return -1;
    }

    if(payload_length > ETHERNET_MTU)
    {
        return -1;
    }

    ethernet_device_t *entry = ethernet_find_device(device);

    if(!entry || !entry->operations || !entry->operations->send_packet)
    {
        return -1;
    }

    uint8_t frame[ETHERNET_FRAME_MAX];

    ethernet_header_t *header = (ethernet_header_t*)frame;

    for(int i = 0; i < ETHERNET_ADDRESS_SIZE; i++)
    {
        header->destination[i] = destination[i];
        header->source[i] = entry->mac_address[i];
    }

    write_be16(header->type, ethernet_type);

    const uint8_t *payload_bytes = (const uint8_t*)payload;

    for(uint16_t i = 0; i < payload_length; i++)
    {
        frame[ETHERNET_HEADER_SIZE + i] = payload_bytes[i];
    }

    uint16_t frame_length = (uint16_t)(ETHERNET_HEADER_SIZE + payload_length);

    return entry->operations->send_packet(device, frame, frame_length);
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;
    
    for(int i = 0; i < ETHERNET_MAX_DEVICES; i++)
    {
        g_devices[i].active = 0;
        g_devices[i].device = 0;
        g_devices[i].operations = NULL;

        for(int j = 0; j < ETHERNET_ADDRESS_SIZE; j++)
        {
            g_devices[i].mac_address[j] = 0;
        }
    }

    g_handler_count = 0;

    if(kernel->device_register_network_listener)
    {
        kernel->device_register_network_listener(ethernet_device_notify);
    }
}

void ddf_driver_exit(void)
{
    if(kernel && kernel->device_unregister_network_listener)
    {
        kernel->device_unregister_network_listener(ethernet_device_notify);
    }

    for(int i = 0; i < ETHERNET_MAX_DEVICES; i++)
    {
        g_devices[i].active = 0;
        g_devices[i].device = NULL;
        g_devices[i].operations = NULL;
    }

    g_handler_count = 0;
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
