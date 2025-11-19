#include "interfaces.h"
#include "pci.h"

void pci_interface_enum_devices(pci_enum_callback_t cb, void *ctx)
{
    pci_enum_devices(cb, ctx);
}

uint32_t pci_interface_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    return pci_config_read32(bus, dev, func, offset);
}

void pci_interface_config_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value)
{
    pci_config_write32(bus, dev, func, offset, value);
}

void pci_interface_enable_device(const pci_device_t *dev)
{
    pci_enable_device(dev);
}

int pci_interface_get_bar(const pci_device_t *dev, uint8_t bar_index, uint32_t *out_base, uint32_t *out_size, int *is_mmio)
{
    return pci_get_bar(dev, bar_index, out_base, out_size, is_mmio);
}
