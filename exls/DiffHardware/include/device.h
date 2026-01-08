#pragma once

#include <stdint.h>

// Device class types
typedef enum device_class
{
    DEVICE_CLASS_UNKNOWN = 0,
    DEVICE_CLASS_INPUT = 1,
    DEVICE_CLASS_DISPLAY = 2,
    DEVICE_CLASS_NETWORK = 3,
    DEVICE_CLASS_TTY = 4,
    DEVICE_CLASS_STORAGE = 5,
    DEVICE_CLASS_SERIAL = 6,
    DEVICE_CLASS_TIMER = 7
} device_class_t;

// Device status
typedef enum device_status
{
    DEVICE_STATUS_OK = 0,
    DEVICE_STATUS_ERROR = 1,
    DEVICE_STATUS_DISABLED = 2,
    DEVICE_STATUS_BUSY = 3
} device_status_t;

// Bus types
#define BUS_TYPE_UNKNOWN    0
#define BUS_TYPE_ISA        1
#define BUS_TYPE_PCI        2
#define BUS_TYPE_USB        3
#define BUS_TYPE_PS2        4
#define BUS_TYPE_VIRTUAL    5

#define DEVICE_NAME_LEN     32
#define DEVICE_DESC_LEN     64

// Device info struct returned by syscall
typedef struct device_info
{
    uint32_t id;
    uint32_t class;
    char name[DEVICE_NAME_LEN];
    char description[DEVICE_DESC_LEN];
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t bus_type;
    uint8_t irq;
    uint32_t status;
} device_info_t;

// Get number of devices, use -1 for all classes
int device_count(int class_filter);

// Get device info by index
int device_get_info(int index, device_info_t *info);

// Helper to get class name string
const char *device_class_name(device_class_t class);

// Helper to get bus type name string
const char *device_bus_name(uint8_t bus_type);

// Helper to get status name string
const char *device_status_name(device_status_t status);
