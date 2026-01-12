#include "interfaces.h"
#include "io.h"
#include "stdio.h"
#include "pic.h"
#include "paging.h"
#include "string.h"
#include "system/irqsw.h"
#include "timer.h"

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
    .timer_now_ms = timer_now_ms,
    .mouse_register = mouse_register,
    .tty_register = tty_register,
    .irq_register_handler = irq_register_handler,
    .irq_unregister_handler = irq_unregister_handler,
    .irqsw_queue = irqsw_queue,
    .alloc_phys_page = alloc_phys_page,
    .free_phys_page = free_phys_page,
    .alloc_phys_pages = alloc_phys_pages,
    .free_phys_pages = free_phys_pages,
    .device_register = device_register,
    .device_unregister = device_unregister,
    .device_class_register = device_class_register,
    .device_bus_register = device_bus_register,
    .device_class_unregister = device_class_unregister,
    .device_bus_unregister = device_bus_unregister,
    .device_register_network_listener = device_register_network_listener,
    .device_unregister_network_listener = device_unregister_network_listener,
    .ipv4_get_config = ipv4_get_config,
    .network_interface_register = network_interface_register,
    .network_interface_unregister = network_interface_unregister,
    .network_interface_get_primary = network_interface_get_primary,
    .network_interface_get_by_device = network_interface_get_by_device,
    .network_interface_receive = network_interface_receive,
    .network_communicator_register_ethernet_type = network_communicator_register_ethernet_type,
    .network_communicator_unregister_ethernet_type = network_communicator_unregister_ethernet_type,
    .network_communicator_transmit = network_communicator_transmit,
    .packet_buffer_alloc = packet_buffer_alloc,
    .packet_buffer_retain = packet_buffer_retain,
    .packet_buffer_release = packet_buffer_release,
    .network_arp_register_resolver = network_arp_register_resolver,
    .network_socket_deliver_icmp_reply = network_socket_deliver_icmp_reply,
    .strlcpy = strlcpy,
};
