#include "drivers/ddf.h"
#include "drivers/device.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

// I/O port addresses that Bochs/QEMU VBE uses
#define VBE_DISPI_IOPORT_INDEX        0x01CE   // VBE IO Port Register
#define VBE_DISPI_IOPORT_DATA         0x01CF   // VBE IO Port Data Register

// Register numbers inside the dispi interface
#define VBE_DISPI_INDEX_ID            0x0      // Which VBE version is present
#define VBE_DISPI_INDEX_XRES          0x1      // Screen width in pixels
#define VBE_DISPI_INDEX_YRES          0x2      // Screen height in pixels
#define VBE_DISPI_INDEX_BPP           0x3      // Bits per pixel (color depth)
#define VBE_DISPI_INDEX_ENABLE        0x4      // Enable/disable the screen
#define VBE_DISPI_INDEX_BANK          0x5      // Memory bank, if not using linear framebuffer
#define VBE_DISPI_INDEX_VIRT_WIDTH    0x6      // Virtual width
#define VBE_DISPI_INDEX_VIRT_HEIGHT   0x7      // Virtual height
#define VBE_DISPI_INDEX_X_OFFSET      0x8      // Horizontal offset inside virtual screen
#define VBE_DISPI_INDEX_Y_OFFSET      0x9      // Vertical offset inside virtual screen

// Known ID values for different Bochs/QEMU VBE versions
#define VBE_DISPI_ID4                 0xB0C4   // VBE version 4
#define VBE_DISPI_ID5                 0xB0C5   // VBE version 5
#define VBE_DISPI_ID6                 0xB0C6   // VBE version 6

// Flags for the ENABLE register
#define VBE_DISPI_ENABLED             0x01     // Turns screen output on
#define VBE_DISPI_LFB_ENABLED         0x40     // Use linear framebuffer instead of banked mode
#define VBE_DISPI_NOCLEARMEM          0x80     // Do not clear video memory when enabling (faster)

static uint32_t g_req_width  = 1024;
static uint32_t g_req_height = 768;
static uint32_t g_req_bpp    = 32;

static kernel_exports_t *kernel = 0;

// This driver does not use interrupts, set IRQ to 0
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

typedef struct vbe_mode_info
{
    uint32_t phys_base;     // Physical base address of framebuffer (from PCI BAR0)
    uint32_t width;         // Visible width in pixels
    uint32_t height;        // Visible height in pixels
    uint32_t bpp;           // Bits per pixel (color depth)
    uint32_t pitch_bytes;   // How many bytes one scanline occupies
    uint32_t pitch_pixels;  // How many pixels wide one scanline is (virtual width)
} vbe_mode_info_t;

typedef struct vbe_device
{
    device_t *dev;
    pci_device_t pci;
    int found;
    vbe_mode_info_t mode;
} vbe_device_t;

// Device registration
static vbe_device_t g_vbe_devices[1];
static vbe_device_t *g_vbe_primary = 0;

// Write into a VBE register.
static inline void vbe_write_reg(uint16_t index, uint16_t value)
{
    kernel->outw(VBE_DISPI_IOPORT_INDEX, index);
    kernel->outw(VBE_DISPI_IOPORT_DATA, value);
}

// Read from a VBE register.
static inline uint16_t vbe_read_reg(uint16_t index)
{
    kernel->outw(VBE_DISPI_IOPORT_INDEX, index);

    return kernel->inw(VBE_DISPI_IOPORT_DATA);
}

static void vbe_pci_enum_cb(const pci_device_t *dev, void *context)
{
    (void)context;

    if (g_vbe_primary && g_vbe_primary->found)
    {
        return;
    }

    if (dev->class_code == 0x03 && dev->subclass == 0x00)
    {
        if (g_vbe_primary)
        {
            g_vbe_primary->pci = *dev;
            g_vbe_primary->found = 1;
        }
    }
}

// Read PCI BAR0 of VGA device, which should point to the linear framebuffer physical base
static uint32_t vga_get_bar0_phys_base(void)
{
    if (g_vbe_primary && !g_vbe_primary->found)
    {
        kernel->pci_enum_devices(vbe_pci_enum_cb, NULL);
    }

    if (!g_vbe_primary || !g_vbe_primary->found)
    {
        kernel->printf("[VBE] VGA device was not found on PCI\n");

        return 0;
    }

    kernel->pci_enable_device(&g_vbe_primary->pci);

    uint32_t base = 0;
    int is_mmio = 0;

    if (kernel->pci_get_bar(&g_vbe_primary->pci, 0, &base, NULL, &is_mmio) != 0 || !is_mmio)
    {
        kernel->printf("[VBE] BAR0 is not a MMIO region\n");

        return 0;
    }

    return base;
}

// Check if the Bochs/QEMU dispi interface exists by reading its ID register.
// If not valid, try writing ID5 and re-reading. If still invalid, there is no VBE.
static int vbe_detect(void)
{
    uint16_t id = vbe_read_reg(VBE_DISPI_INDEX_ID);

    if (id < 0xB0C0 || id > 0xB0C6)
    {
        vbe_write_reg(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);
        id = vbe_read_reg(VBE_DISPI_INDEX_ID);
        if (id < 0xB0C0 || id > 0xB0C6)
        {
            return -1;
        }
    }

    return 0;
}

// Enable VBE flags
static void vbe_enable(uint16_t flags)
{
    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, flags);
}

// Set video mode
static int vbe_set_mode(uint32_t w, uint32_t h, uint32_t bpp)
{
    // Select a safe ID
    vbe_write_reg(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);

    // Disable output while changing registers to avoid flicker
    vbe_enable(0);

    // Set the visible data
    vbe_write_reg(VBE_DISPI_INDEX_XRES, (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_YRES, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_BPP,  (uint16_t)bpp);

    // Mirror visible data into the virtual data
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);

    // Enable output and linear framebuffer and skip VRAM clear for speed
    vbe_enable((uint16_t)(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM));

    // Read back visible data
    {
        uint16_t rw = vbe_read_reg(VBE_DISPI_INDEX_XRES);
        uint16_t rh = vbe_read_reg(VBE_DISPI_INDEX_YRES);
        uint16_t rb = vbe_read_reg(VBE_DISPI_INDEX_BPP);

        if (rw != (uint16_t)w || rh != (uint16_t)h || rb != (uint16_t)bpp)
        {
            return -1;
        }
    }

    // Clamp virtual data into valid bounds since some firmware returns odd values
    {
        uint16_t vwid = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
        uint16_t vhgt = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);

        uint16_t min_w = (uint16_t)w;
        uint16_t min_h = (uint16_t)h;
        uint16_t max_w = 8192;
        uint16_t max_h = 8192;

        int need_fix = 0;

        if (vwid == 0 || vwid < min_w || vwid > max_w)
        {
            vwid = min_w;
            need_fix = 1;
        }

        if (vhgt == 0 || vhgt < min_h || vhgt > max_h)
        {
            vhgt = min_h;
            need_fix = 1;
        }

        if (need_fix)
        {
            // Weird VBE Hack: disable then re enable
            vbe_enable(0);
            vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  vwid);
            vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, vhgt);
            vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
            vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
            vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);
            vbe_enable((uint16_t)(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM));
        }
    }

    return 0;
}

// Provide a pointer to current mode info
static vbe_mode_info_t *vbe_get_info(void)
{
    return g_vbe_primary ? &g_vbe_primary->mode : NULL;
}

// Device operations
static int display_dev_get_current_mode(device_t *dev, display_mode_t *mode)
{
    vbe_device_t *vbe = (vbe_device_t *)dev->private_data;

    if (!mode)
    {
        return -1;
    }

    if (!vbe)
    {
        return -1;
    }

    mode->width = vbe->mode.width;
    mode->height = vbe->mode.height;
    mode->bpp = vbe->mode.bpp;
    mode->pitch = vbe->mode.pitch_bytes;
    mode->phys_base = vbe->mode.phys_base;

    return 0;
}

static int display_dev_set_mode(device_t *dev, uint32_t width, uint32_t height, uint32_t bpp)
{
    vbe_device_t *vbe = (vbe_device_t *)dev->private_data;

    if (!vbe)
    {
        return -1;
    }

    return vbe_set_mode(width, height, bpp);
}

static display_device_t g_display_ops =
{
    .get_current_mode = display_dev_get_current_mode,
    .set_mode = display_dev_set_mode,
    .get_mode_count = 0,
    .get_mode_info = 0,
    .get_framebuffer = 0,
    .get_framebuffer_size = 0,
    .clear = 0,
    .put_pixel = 0,
    .fill_rect = 0,
};

// Driver init entry point called by the module loader
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;
    g_vbe_primary = &g_vbe_devices[0];
    g_vbe_primary->dev = 0;
    g_vbe_primary->found = 0;
    g_vbe_primary->mode.phys_base = 0;
    g_vbe_primary->mode.width = 0;
    g_vbe_primary->mode.height = 0;
    g_vbe_primary->mode.bpp = 0;
    g_vbe_primary->mode.pitch_bytes = 0;
    g_vbe_primary->mode.pitch_pixels = 0;

    // Detect Bochs dispi
    if (vbe_detect() != 0)
    {
        exports->printf("[VBE] No Bochs or QEMU dispi detected\n");

        return;
    }

    // Get the framebuffer physical address
    uint32_t lfb_phys = vga_get_bar0_phys_base();

    if (lfb_phys == 0)
    {
        exports->printf("[VBE] Failed to obtain LFB physical base via PCI\n");

        return;
    }

    // Program the requested mode
    if (vbe_set_mode(g_req_width, g_req_height, g_req_bpp) != 0)
    {
        exports->printf("[VBE] Failed to set mode %ux%u@%u\n",
                        (unsigned)g_req_width, (unsigned)g_req_height, (unsigned)g_req_bpp);

        return;
    }

    // Read registers and compute the correct pitch values
    {
        uint16_t rx   = vbe_read_reg(VBE_DISPI_INDEX_XRES);
        uint16_t ry   = vbe_read_reg(VBE_DISPI_INDEX_YRES);
        uint16_t rbpp = vbe_read_reg(VBE_DISPI_INDEX_BPP);
        uint16_t vwid = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
        uint16_t vhgt = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);

        if (vwid == 0)
        {
            vwid = rx;
        }

        if (vhgt == 0)
        {
            vhgt = ry;
        }

        if (vwid < rx || vwid > 8192)
        {
            vwid = rx;
        }

        if (vhgt < ry || vhgt > 8192)
        {
            vhgt = ry;
        }

        g_vbe_primary->mode.width        = (uint32_t)rx;
        g_vbe_primary->mode.height       = (uint32_t)ry;
        g_vbe_primary->mode.bpp          = (uint32_t)rbpp;
        g_vbe_primary->mode.pitch_pixels = (uint32_t)vwid;

        // Compute pitch in bytes
        uint32_t bpp_bytes  = (g_vbe_primary->mode.bpp + 7u) / 8u;
        g_vbe_primary->mode.pitch_bytes  = g_vbe_primary->mode.pitch_pixels * bpp_bytes;
        g_vbe_primary->mode.phys_base    = lfb_phys;
    }

    // Register the VBE driver in the kernel
    if (exports->vbe_register)
    {
        exports->vbe_register(g_vbe_primary->mode.phys_base,
                              g_vbe_primary->mode.width,
                              g_vbe_primary->mode.height,
                              g_vbe_primary->mode.bpp,
                              g_vbe_primary->mode.pitch_bytes);
    }

    // Register device
    g_vbe_primary->dev = exports->device_register(DEVICE_CLASS_DISPLAY, "vbe_qemu", &g_display_ops);

    if (g_vbe_primary->dev)
    {
        g_vbe_primary->dev->bus_type = BUS_TYPE_PCI;
        g_vbe_primary->dev->vendor_id = g_vbe_primary->pci.vendor_id;
        g_vbe_primary->dev->device_id = g_vbe_primary->pci.device_id;
        g_vbe_primary->dev->mmio_base = g_vbe_primary->mode.phys_base;
        g_vbe_primary->dev->private_data = g_vbe_primary;
        exports->strlcpy(g_vbe_primary->dev->description, "QEMU/Bochs VBE Display", sizeof(g_vbe_primary->dev->description));
    }

    exports->printf("[DRIVER] VBE Graphics Driver Installed\n");
}

// This driver does not use interrupts
void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}

void ddf_driver_exit(void)
{
    if (g_vbe_primary && g_vbe_primary->dev)
    {
        kernel->device_unregister(g_vbe_primary->dev);
        g_vbe_primary->dev = 0;
    }

    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, 0);
    kernel->printf("[DRIVER] VBE Graphics Driver Uninstalled\n");
}

void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name)
{
    (void)module_base;
    (void)header;

    const char target[] = "vbe_get_info";
    const char *p = name;
    const char *q = target;

    while (*p && *q && *p == *q)
    {
        p++;
        q++;
    }

    if (*p == '\0' && *q == '\0')
    {
        return (void *)&vbe_get_info;
    }

    return NULL;
}
