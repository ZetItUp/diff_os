#pragma once

#include "stdint.h"
#include "stdarg.h"
#include "pci.h"
#include "irq.h"
#include "drivers/device.h"
#include "drivers/ipv4_config.h"
#include "network/arp_service.h"
#include "network/network_communicator.h"
#include "network/network_interface.h"
#include "network/socket.h"
#include "system/irqsw.h"

// Mouse packet (relative movement + buttons)
typedef struct mouse_packet
{
    int8_t dx;
    int8_t dy;
    uint8_t buttons; // bit0=L, bit1=R, bit2=M
} __attribute__((packed)) mouse_packet_t;

// Exposed kernel function hooks (used by drivers)
typedef struct kernel_exports
{
    unsigned char (*inb)(unsigned short port);
    void (*outb)(unsigned short port, unsigned char data);
    unsigned short (*inw)(unsigned short port);
    void (*outw)(unsigned short port, unsigned short data);
    void (*outl)(uint16_t port, uint32_t value);
    uint32_t (*inl)(uint16_t port);
    void (*io_wait)(void);

    int (*printf)(const char *fmt, ...);
    int (*vprintf)(const char *fmt, va_list ap);
    void (*pic_clear_mask)(uint8_t);
    void (*pic_set_mask)(uint8_t);

    void *(*map_physical)(uint32_t phys, uint32_t size, uint32_t flags);  // Map physical memory into VA

    void (*keyboard_register)(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));  // Plug keyboard backend

    void (*vbe_register)(uint32_t phys_base, uint32_t width, uint32_t height, uint32_t bpp, uint32_t pitch);  // Register VBE mode
    void (*pci_enum_devices)(pci_enum_callback_t cb, void *ctx);
    uint32_t (*pci_config_read32)(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
    void (*pci_config_write32)(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value);
    void (*pci_enable_device)(const pci_device_t *dev);
    int (*pci_get_bar)(const pci_device_t *dev, uint8_t bar_index, uint32_t *out_base, uint32_t *out_size, int *is_mmio);
    uint64_t (*timer_now_ms)(void);
    void (*mouse_register)(int (*read_fn)(mouse_packet_t*), int (*read_block_fn)(mouse_packet_t*)); // Plug mouse backend
    void (*tty_register)(int (*read_fn)(char*, unsigned),
                         int (*write_fn)(const char*, unsigned),
                         void (*input_fn)(char),
                         void (*set_canonical_fn)(int),
                         void (*set_echo_fn)(int),
                         int (*available_fn)(void),
                         int (*read_output_fn)(char*, unsigned)); // Plug TTY backend
    int (*irq_register_handler)(uint8_t irq, irq_handler_t handler, void *context);
    int (*irq_unregister_handler)(uint8_t irq, irq_handler_t handler, void *context);
    int (*irqsw_queue)(irqsw_handler_t handler, void *context);

    // DMA memory allocation (returns physical addresses)
    uint32_t (*alloc_phys_page)(void);          // Allocate 4KB physical page, returns phys addr
    void (*free_phys_page)(uint32_t addr);      // Free physical page
    uint32_t (*alloc_phys_pages)(uint32_t count);  // Allocate N contiguous physical pages
    void (*free_phys_pages)(uint32_t addr, uint32_t count);  // Free N contiguous pages

    // Device registration
    device_t *(*device_register)(device_class_t class, const char *name, void *operations);
    void (*device_unregister)(device_t *dev);
    int (*device_class_register)(device_class_t class, const char *name);
    int (*device_bus_register)(uint8_t bus_type, const char *name);
    int (*device_class_unregister)(device_class_t class);
    int (*device_bus_unregister)(uint8_t bus_type);
    int (*device_register_network_listener)(network_device_notify_t callback);
    int (*device_unregister_network_listener)(network_device_notify_t callback);
    int (*ipv4_get_config)(ipv4_config_t *out);
    network_interface_t *(*network_interface_register)(struct device *device,
        network_interface_ops_t *ops,
        const uint8_t mac_address[6],
        uint32_t mtu,
        void *private_data);
    void (*network_interface_unregister)(network_interface_t *interface);
    network_interface_t *(*network_interface_get_primary)(void);
    network_interface_t *(*network_interface_get_by_device)(struct device *device);
    int (*network_interface_receive)(network_interface_t *interface, packet_buffer_t *packet);
    int (*network_communicator_register_ethernet_type)(uint16_t ethernet_type,
        network_communicator_handler_t handler,
        void *context);
    int (*network_communicator_unregister_ethernet_type)(uint16_t ethernet_type,
        network_communicator_handler_t handler,
        void *context);
    int (*network_communicator_transmit)(network_interface_t *interface, packet_buffer_t *packet);
    packet_buffer_t *(*packet_buffer_alloc)(uint32_t capacity, uint32_t head);
    void (*packet_buffer_retain)(packet_buffer_t *packet);
    void (*packet_buffer_release)(packet_buffer_t *packet);
    int (*network_arp_register_resolver)(network_arp_resolve_t resolver);
    int (*network_socket_deliver_icmp_reply)(const uint8_t source_ip[4],
        uint16_t identifier,
        uint16_t sequence,
        const uint8_t *payload,
        uint16_t payload_length);

    // String utilities
    size_t (*strlcpy)(char *dst, const char *src, size_t siz);
} __attribute__((packed)) kernel_exports_t;

// Keyboard-facing exports
typedef struct keyboard_exports
{
    int (*keyboard_read)(uint8_t *out);
    uint8_t (*keyboard_read_blocking)(void);
} __attribute__((packed)) keyboard_exports_t;

// Modifier key flags
#define KB_MOD_SHIFT  0x01
#define KB_MOD_CTRL   0x02
#define KB_MOD_ALT    0x04
#define KB_MOD_CAPS   0x08

typedef struct keyboard_event
{
    uint8_t pressed;
    uint8_t key;
    uint8_t modifiers;  // KB_MOD_* flags
} keyboard_event_t;

// Shared VBE info
typedef struct vbe_exports
{
    volatile void *frame_buffer;

    uint32_t phys_base;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t pitch;
} __attribute__((packed)) vbe_exports_t;

// Kernel exports instance
extern kernel_exports_t g_exports;

// Mouse-facing exports
typedef struct mouse_exports
{
    int (*mouse_read)(mouse_packet_t *out);
    int (*mouse_read_blocking)(mouse_packet_t *out);
} __attribute__((packed)) mouse_exports_t;

extern mouse_exports_t g_mouse;
void mouse_register(int (*read_fn)(mouse_packet_t*), int (*read_block_fn)(mouse_packet_t*));
void mouse_init(void);
void mouse_drain(void);
int mouse_try_get_packet(mouse_packet_t *packet);
int mouse_get_packet(mouse_packet_t *packet);

// TTY-facing exports
typedef struct tty_exports
{
    int (*tty_read)(char *buf, unsigned count);
    int (*tty_write)(const char *buf, unsigned count);
    void (*tty_input_char)(char c);
    void (*tty_set_canonical)(int enabled);
    void (*tty_set_echo)(int enabled);
    int (*tty_input_available)(void);
    int (*tty_read_output)(char *buf, unsigned count);
} __attribute__((packed)) tty_exports_t;

extern tty_exports_t g_tty;
void tty_register(
    int (*read_fn)(char*, unsigned),
    int (*write_fn)(const char*, unsigned),
    void (*input_fn)(char),
    void (*set_canonical_fn)(int),
    void (*set_echo_fn)(int),
    int (*available_fn)(void),
    int (*read_output_fn)(char*, unsigned)
);
int tty_read(char *buf, unsigned count);
int tty_write(const char *buf, unsigned count);
void tty_input_char(char c);
void tty_set_canonical(int enabled);
void tty_set_echo(int enabled);
int tty_input_available(void);
int tty_read_output(char *buf, unsigned count);

// Mouse state tracking
void mouse_update_state(void);
int mouse_get_pos(void);
void mouse_set_pos(int x, int y);
void mouse_set_bounds(int max_x, int max_y);
uint8_t mouse_get_buttons_down(void);
uint8_t mouse_get_buttons_pressed(void);
uint8_t mouse_get_buttons_clicked(void);

// Memory helpers
extern void* kernel_map_physical_addr(uint32_t phys, uint32_t size, uint32_t flags);

// Keyboard
extern keyboard_exports_t g_keyboard;
void keyboard_register(int (*read_fn)(uint8_t*), uint8_t (*block_fn)(void));
void keyboard_init(void);
void keyboard_drain(void);
int keyboard_get_event(keyboard_event_t *event);
int keyboard_try_get_event(keyboard_event_t *event);
int keyboard_trygetch(uint8_t *out);
uint8_t keyboard_getch(void);

// Console colors 
int console_set_colors_kernel(uint8_t fg, uint8_t bg);
void console_get_colors_kernel(uint8_t *out_fg, uint8_t *out_bg);

// VBE registration and state
extern vbe_exports_t g_vbe;
void vbe_register(uint32_t phys_base, uint32_t width, uint32_t height, uint32_t bpp, uint32_t pitch);
int  vbe_restore_default_mode(void);
int  vbe_is_default_mode(void);
void vbe_clear(uint32_t argb);
void vbe_release_owner(int pid);

// PCI interface wrappers
void pci_interface_enum_devices(pci_enum_callback_t cb, void *ctx);
uint32_t pci_interface_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset);
void pci_interface_config_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value);
void pci_interface_enable_device(const pci_device_t *dev);
int pci_interface_get_bar(const pci_device_t *dev, uint8_t bar_index, uint32_t *out_base, uint32_t *out_size, int *is_mmio);
