#pragma once

#include "stdint.h"
#include "stddef.h"

// Device Classes
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


// Input Device Types
typedef enum input_type
{
    INPUT_TYPE_UNKNOWN = 0,
    INPUT_TYPE_KEYBOARD = 1,
    INPUT_TYPE_MOUSE = 2,
    INPUT_TYPE_GAMEPAD = 3
} input_type_t;


// Device Status Flags
typedef enum device_status
{
    DEVICE_STATUS_OK = 0,
    DEVICE_STATUS_ERROR = 1,
    DEVICE_STATUS_DISABLED = 2,
    DEVICE_STATUS_BUSY = 3
} device_status_t;

struct ddf_module;
struct device;


// Input Device
typedef struct input_device
{
    // Get input type
    input_type_t (*get_type)(struct device *dev);
    // Returns available events count
    int (*poll_available)(struct device *dev);

    // Keyboard

    // Non blocking read
    int (*read_scancode)(struct device *dev, uint8_t *out);
    // Blocking read
    uint8_t (*read_scancode_blocking)(struct device *dev);
    // LED Control (Num/Caps/Scroll-lock)
    int (*set_leds)(struct device *dev, uint8_t led_state);

    // Mouse

    // Non blocking read
    int (*read_packet)(struct device *dev, void *packet_out);
    // Blocking read
    int (*read_packet_blocking)(struct device *dev, void *packet_out);
} input_device_t;


// Network Device
typedef struct network_device
{
    // Get MAC
    int (*get_mac)(struct device *dev, uint8_t mac[6]);
    
    // Transmit
    int (*send_packet)(struct device *dev, const void *data, uint16_t length);
    // Receive (Non blocking)
    int (*receive_packet)(struct device *dev, void *buffer, uint16_t buf_size);
    // Check RX Queue Size
    int (*packets_available)(struct device *dev);

    // Link Status (1 = Up, 0 = Down)
    int (*get_link_status)(struct device *dev);
    // Get Link Speed
    uint32_t (*get_speed)(struct device *dev);

    // Configuration
    int (*set_promiscuous)(struct device *dev, int enabled);
    int (*set_multicast)(struct device *dev, int enabled);
} network_device_t;


// Display Device

// Display Mode
typedef struct display_mode
{
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t pitch;
    uint32_t phys_base;
} display_mode_t;


// Display Device
typedef struct display_device
{
    // Mode information
    int (*get_current_mode)(struct device *dev, display_mode_t *mode);
    int (*set_mode)(struct device *dev, uint32_t width, uint32_t height, uint32_t bpp);
    int (*get_mode_count)(struct device *dev);
    int (*get_mode_info)(struct device *dev, int index, display_mode_t *mode);

    // Framebuffer Access
    // Returns Mapped VA
    void *(*get_framebuffer)(struct device *dev);
    // Get Framebuffer Size
    uint32_t (*get_framebuffer_size)(struct device *dev);

    // Drawing Primitives
    void (*clear)(struct device *dev, uint32_t color);
    void (*put_pixel)(struct device *dev, uint32_t x, uint32_t y, uint32_t color);
    void (*fill_rect)(struct device *dev, uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t color);
} display_device_t;


// TTY Device
typedef struct tty_device
{
    // I/O
    int (*read)(struct device *dev, char *buffer, unsigned count);
    int (*write)(struct device *dev, const char *buffer, unsigned count);

    // Input
    void (*input_char)(struct device *dev, char c);
    int (*input_available)(struct device *dev);

    // Mode Control
    void (*set_canonical)(struct device *dev, int enabled);
    void (*set_echo)(struct device *dev, int enabled);
    int (*get_canonical)(struct device *dev);
    int (*get_echo)(struct device *dev);

    // Output Capture
    int (*read_output)(struct device *dev, char *buffer, unsigned count);
} tty_device_t;


//
// Generic Device
//
#define DEVICE_NAME_LEN     32
#define DEVICE_DESC_LEN     64

typedef struct device
{
    // Identification
    uint32_t id;                        // Unique Device ID
    device_class_t class;               // Device Class
    char name[DEVICE_NAME_LEN];         // Device Name
    char description[DEVICE_DESC_LEN];  // Device Description

    // Hardware Information
    uint16_t vendor_id;                 // PCI Vendor ID
    uint16_t device_id;                 // PCI Device ID
    uint8_t bus_type;                   // Bus Type
    uint8_t irq;                        // IRQ Number
    uint32_t io_base;                   // I/O Port Base
    uint32_t mmio_base;                 // MMIO Base
                                        
    // Status
    device_status_t status;

    // Driver Module Owner
    struct ddf_module *owner;           // Which driver owns this device

    // Class Operations
    void *operations;

    // Lifecycle Hooks
    int (*stop)(struct device *dev);
    void (*cleanup)(struct device *dev);

    void *private_data;

    // Reference Tracking
    int refcount;
    int removing;

    struct device *next;
} device_t;


//
// Bus Types
//
#define BUS_TYPE_UNKNOWN    0
#define BUS_TYPE_ISA        1
#define BUS_TYPE_PCI        2
#define BUS_TYPE_USB        3
#define BUS_TYPE_PS2        4
#define BUS_TYPE_VIRTUAL    5

#define DEVICE_CLASS_NAME_LEN  16
#define DEVICE_BUS_NAME_LEN    16


//
// Device API
//

// Registration
device_t *device_register(device_class_t class, const char *name, void *operations);
void device_unregister(device_t *dev);

// Class / Bus Registry
void device_registry_init(void);
int device_class_register(device_class_t class, const char *name);
int device_bus_register(uint8_t bus_type, const char *name);
int device_class_unregister(device_class_t class);
int device_bus_unregister(uint8_t bus_type);
const char *device_class_name(device_class_t class);
const char *device_bus_name(uint8_t bus_type);

typedef void (*network_device_notify_t)(device_t *dev, int added);

int device_register_network_listener(network_device_notify_t callback);
int device_unregister_network_listener(network_device_notify_t callback);

// Get Device
device_t *device_get_by_id(uint32_t id);
device_t *device_get_by_name(const char *name);

// Device Enumeration
int device_get_count(void);
int device_get_count_by_class(device_class_t class);
device_t *device_get_by_index(int index);
int device_enumerate_class(device_class_t class, device_t **out, int max_count);
void device_put(device_t *dev);

// Iteration
device_t *device_first(void);
device_t *device_next(device_t *dev);


//
// Userland Stuff
//

// Device Information
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

// Convert device_t to device_info_t
void device_to_info(device_t *dev, device_info_t *info);
