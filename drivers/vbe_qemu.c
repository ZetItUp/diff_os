#include "drivers/ddf.h"
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

// Global mode info instance
static vbe_mode_info_t g_mode =
{
    .phys_base = 0,
    .width = 0,
    .height = 0,
    .bpp = 0,
    .pitch_bytes = 0,
    .pitch_pixels = 0
};

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

// Read 32-bit PCI config space using type 1 mechanism (CF8/CFC).
static inline uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off)
{
    uint32_t addr = 0x80000000u
                  | ((uint32_t)bus  << 16)
                  | ((uint32_t)dev  << 11)
                  | ((uint32_t)func << 8)
                  | (off & 0xFC);

    kernel->outl(0xCF8, addr);
    return kernel->inl(0xCFC);
}

// Scan all PCI buses and look for a device with class=0x03 (Display Controller) and subclass=0x00 (VGA).
static int pci_find_vga(uint8_t *out_bus, uint8_t *out_dev, uint8_t *out_func)
{
    for (uint16_t bus = 0; bus < 256; bus++)
    {
        for (uint8_t dev = 0; dev < 32; dev++)
        {
            for (uint8_t func = 0; func < 8; func++)
            {
                // Read Vendor ID and Device ID
                // If 0xFFFF there is no device here
                uint32_t id0 = pci_cfg_read32((uint8_t)bus, dev, func, 0x00);
                if ((id0 & 0xFFFF) == 0xFFFF)
                {
                    // Function 0 absent means whole device slot is empty
                    if (func == 0)
                    {
                        break;
                    }
                    else
                    {
                        continue;
                    }
                }

                // Read code register: (31-24)=base class, (23-16)=subclass
                uint32_t class_reg = pci_cfg_read32((uint8_t)bus, dev, func, 0x08);
                uint8_t base_class = (uint8_t)((class_reg >> 24) & 0xFF);
                uint8_t sub_class  = (uint8_t)((class_reg >> 16) & 0xFF);

                // Found VGA device
                if (base_class == 0x03 && sub_class == 0x00)
                {
                    *out_bus  = (uint8_t)bus;
                    *out_dev  = dev;
                    *out_func = func;
                    return 0;
                }

                // If function 0 is not multifunction, skip other funcs
                uint32_t head = pci_cfg_read32((uint8_t)bus, dev, func, 0x0C);
                if (func == 0 && ((head >> 16) & 0x80) == 0)
                {
                    break;
                }
            }
        }
    }

    return -1;
}

// Read PCI BAR0 of VGA device, which should point to the linear framebuffer physical base
static uint32_t vga_get_bar0_phys_base(void)
{
    uint8_t bus;
    uint8_t dev;
    uint8_t func;

    if (pci_find_vga(&bus, &dev, &func) != 0)
    {
        kernel->printf("[VBE] VGA device was not found on PCI\n");
        return 0;
    }

    uint32_t bar0 = pci_cfg_read32(bus, dev, func, 0x10);

    // BAR0 should be memory space, not IO space.
    if ((bar0 & 0x1u) != 0)
    {
        kernel->printf("[VBE] BAR0 is I O space but memory BAR was expected\n");
        return 0;
    }

    // Mask out lower bits that are flags.
    uint32_t phys = bar0 & ~0xFu;

    if (phys == 0)
    {
        kernel->printf("[VBE] BAR0 returned zero which is unexpected\n");
        return 0;
    }

    return phys;
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
    return &g_mode;
}

// Driver init entry point called by the module loader
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

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

        g_mode.width        = (uint32_t)rx;
        g_mode.height       = (uint32_t)ry;
        g_mode.bpp          = (uint32_t)rbpp;
        g_mode.pitch_pixels = (uint32_t)vwid;

        // Compute pitch in bytes
        uint32_t bpp_bytes  = (g_mode.bpp + 7u) / 8u;
        g_mode.pitch_bytes  = g_mode.pitch_pixels * bpp_bytes;
        g_mode.phys_base    = lfb_phys;
    }

    // Register the VBE driver in the kernel
    if (exports->vbe_register)
    {
        exports->vbe_register(g_mode.phys_base,
                              g_mode.width,
                              g_mode.height,
                              g_mode.bpp,
                              g_mode.pitch_bytes);
    }

    exports->printf("[DRIVER] VBE Graphics driver installed\n");
}

// This driver does not use interrupts
void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}

void ddf_driver_exit(void)
{
    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, 0);
    kernel->printf("[DRIVER] VBE Graphics driver uninstalled\n");
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

