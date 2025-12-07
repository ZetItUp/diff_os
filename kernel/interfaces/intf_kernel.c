#include "interfaces.h"
#include "io.h"
#include "stdio.h"
#include "pic.h"

kernel_exports_t g_exports = 
{
    .inw = inw,
    .outw = outw,
    .inb = inb,
    .outb = outb,
    .outl = outl,
    .inl = inl,
    .io_wait = io_wait,
    .printf = printf,
    .vprintf = vprintf,
    .pic_clear_mask = pic_clear_mask,
    .pic_set_mask = pic_set_mask,
    .keyboard_register = keyboard_register,
    .map_physical = kernel_map_physical_addr,
    .vbe_register = vbe_register,
    .pci_enum_devices = pci_interface_enum_devices,
    .pci_config_read32 = pci_interface_config_read32,
    .pci_config_write32 = pci_interface_config_write32,
    .pci_enable_device = pci_interface_enable_device,
    .pci_get_bar = pci_interface_get_bar,
    .mouse_register = mouse_register,
};
