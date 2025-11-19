#pragma once

#include "stdint.h"

// Maximum buses/devices/functions our simple walker will scan
#define PCI_MAX_BUS   256
#define PCI_MAX_DEV   32
#define PCI_MAX_FUNC  8

// Legacy config space ports (0xCF8/0xCFC)
#define PCI_CONFIG_ADDR 0xCF8
#define PCI_CONFIG_DATA 0xCFC

// Standard config-space offsets
#define PCI_VENDOR_ID   0x00
#define PCI_DEVICE_ID   0x02
#define PCI_COMMAND     0x04
#define PCI_STATUS      0x06
#define PCI_PROG_IF     0x09
#define PCI_SUBCLASS    0x0A
#define PCI_CLASS_CODE  0x0B
#define PCI_HEADER_TYPE 0x0E
#define PCI_BAR0        0x10

// Basic descriptor returned for each discovered device
typedef struct pci_device
{
    uint8_t  bus;
    uint8_t  device;
    uint8_t  function;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t  class_code;
    uint8_t  subclass;
    uint8_t  prog_if;
    uint8_t  header_type;
} pci_device_t;

// Initialize PCI subsystem and perform bus scan
void pci_init(void);

typedef void (*pci_enum_callback_t)(const pci_device_t *dev, void *ctx);
// Iterate over devices discovered by pci_init
void pci_enum_devices(pci_enum_callback_t cb, void *ctx);

// Raw config-space helpers
uint32_t pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
void     pci_config_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value);

// Convenience helpers for drivers
void pci_enable_device(const pci_device_t *dev);
int  pci_get_bar(const pci_device_t *dev, uint8_t bar_index, uint32_t *out_base, uint32_t *out_size, int *is_mmio);
