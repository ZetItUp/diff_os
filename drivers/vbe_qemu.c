// All comments are written in English (per user preference).
// Allman brace style is used consistently.

#include "drivers/ddf.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

// ---- Bochs/QEMU VBE (dispi) I/O ports and registers ----
#define VBE_DISPI_IOPORT_INDEX        0x01CE
#define VBE_DISPI_IOPORT_DATA         0x01CF

#define VBE_DISPI_INDEX_ID            0x0
#define VBE_DISPI_INDEX_XRES          0x1
#define VBE_DISPI_INDEX_YRES          0x2
#define VBE_DISPI_INDEX_BPP           0x3
#define VBE_DISPI_INDEX_ENABLE        0x4
#define VBE_DISPI_INDEX_BANK          0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH    0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT   0x7
#define VBE_DISPI_INDEX_X_OFFSET      0x8
#define VBE_DISPI_INDEX_Y_OFFSET      0x9

// Common Bochs dispi IDs
#define VBE_DISPI_ID4                 0xB0C4
#define VBE_DISPI_ID5                 0xB0C5
#define VBE_DISPI_ID6                 0xB0C6

// Enable flags
#define VBE_DISPI_ENABLED             0x01
#define VBE_DISPI_LFB_ENABLED         0x40
#define VBE_DISPI_NOCLEARMEM          0x80

// Requested default mode
static uint32_t g_req_width  = 1024;
static uint32_t g_req_height = 768;
static uint32_t g_req_bpp    = 32;

// Kernel exports from host (filled in driver init)
static kernel_exports_t *kernel = 0;

// No IRQ for this driver
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

// ---- Minimal mode info structure exposed for symbol lookup ----
typedef struct vbe_mode_info
{
    uint32_t phys_base;     // Physical LFB base (PCI BAR0)
    uint32_t width;         // Actual XRES
    uint32_t height;        // Actual YRES
    uint32_t bpp;           // Actual BPP
    uint32_t pitch_bytes;   // Bytes per scanline
    uint32_t pitch_pixels;  // Pixels per scanline
}
vbe_mode_info_t;

static vbe_mode_info_t g_mode =
{
    .phys_base = 0,
    .width = 0,
    .height = 0,
    .bpp = 0,
    .pitch_bytes = 0,
    .pitch_pixels = 0
};

// ---- I/O helpers for dispi ----
static inline void vbe_write_reg(uint16_t index, uint16_t value)
{
    kernel->outw(VBE_DISPI_IOPORT_INDEX, index);
    kernel->outw(VBE_DISPI_IOPORT_DATA, value);
}

static inline uint16_t vbe_read_reg(uint16_t index)
{
    kernel->outw(VBE_DISPI_IOPORT_INDEX, index);
    return kernel->inw(VBE_DISPI_IOPORT_DATA);
}

// ---- PCI config space helpers ----
static inline uint32_t pci_cfg_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off)
{
    // Type 1 config mechanism
    uint32_t addr = 0x80000000u
                  | ((uint32_t)bus  << 16)
                  | ((uint32_t)dev  << 11)
                  | ((uint32_t)func << 8)
                  | (off & 0xFC);

    kernel->outl(0xCF8, addr);
    return kernel->inl(0xCFC);
}

static int pci_find_vga(uint8_t *out_bus, uint8_t *out_dev, uint8_t *out_func)
{
    // Search buses for Display Controller (class 0x03), VGA (subclass 0x00).
    for (uint16_t bus = 0; bus < 256; bus++)
    {
        for (uint8_t dev = 0; dev < 32; dev++)
        {
            // func loop: break early if not multifunction and func 0 is empty.
            for (uint8_t func = 0; func < 8; func++)
            {
                uint32_t id0 = pci_cfg_read32((uint8_t)bus, dev, func, 0x00);
                if ((id0 & 0xFFFF) == 0xFFFF)
                {
                    if (func == 0) { break; }
                    else { continue; }
                }

                uint32_t class_reg = pci_cfg_read32((uint8_t)bus, dev, func, 0x08);
                uint8_t base_class = (uint8_t)((class_reg >> 24) & 0xFF);
                uint8_t sub_class  = (uint8_t)((class_reg >> 16) & 0xFF);

                if (base_class == 0x03 && sub_class == 0x00)
                {
                    *out_bus  = (uint8_t)bus;
                    *out_dev  = dev;
                    *out_func = func;
                    return 0;
                }

                // If not multifunction, stop at func 0
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

static uint32_t vga_get_bar0_phys_base(void)
{
    uint8_t bus, dev, func;

    if (pci_find_vga(&bus, &dev, &func) != 0)
    {
        kernel->printf("[VBE] No VGA device found via PCI\n");
        return 0;
    }

    // Read BAR0 at offset 0x10. Expect a memory BAR (bit0 == 0).
    uint32_t bar0 = pci_cfg_read32(bus, dev, func, 0x10);

    if ((bar0 & 0x1u) != 0)
    {
        kernel->printf("[VBE] BAR0 is I/O space, expected memory BAR\n");
        return 0;
    }

    // Mask off type/flags. For 64-bit BARs, BAR1 would hold the upper dword.
    // QEMU std-VGA LFB is 32-bit.
    uint32_t phys = bar0 & ~0xFu;

    if (phys == 0)
    {
        kernel->printf("[VBE] BAR0 returned 0 (unexpected)\n");
        return 0;
    }

    return phys;
}

// ---- dispi mode programming ----
static int vbe_detect(void)
{
    // Read ID; accept range 0xB0C0..0xB0C6. If not in range, try set to ID5 and re-read.
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

static void vbe_enable(uint16_t flags)
{
    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, flags);
}

static int vbe_set_mode(uint32_t w, uint32_t h, uint32_t bpp)
{
    // Select a known-good ID (ID5).
    vbe_write_reg(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);

    // Disable while programming.
    vbe_enable(0);

    // Program visible geometry.
    vbe_write_reg(VBE_DISPI_INDEX_XRES, (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_YRES, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_BPP,  (uint16_t)bpp);

    // Program virtual geometry to match.
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);

    // Enable LFB (no clear for speed).
    vbe_enable(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM);

    // Verify visible mode.
    {
        uint16_t rw = vbe_read_reg(VBE_DISPI_INDEX_XRES);
        uint16_t rh = vbe_read_reg(VBE_DISPI_INDEX_YRES);
        uint16_t rb = vbe_read_reg(VBE_DISPI_INDEX_BPP);

        if ((rw != (uint16_t)w) || (rh != (uint16_t)h) || (rb != (uint16_t)bpp))
        {
            return -1;
        }
    }

    // Ensure virtual geometry sane (guard against crazy values).
    {
        uint16_t vwid = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
        uint16_t vhgt = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);

        // Acceptable bounds: [visible, 8192], 0 means “use visible”.
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
            // Some firmwares only latch changes cleanly if we toggle ENABLE.
            vbe_enable(0);
            vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  vwid);
            vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, vhgt);
            vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
            vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
            vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);
            vbe_enable(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM);
        }
    }

    return 0;
}

static vbe_mode_info_t *vbe_get_info(void)
{
    return &g_mode;
}

// ---- Driver entry points ----
void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // 1) Confirm Bochs/QEMU dispi is present.
    if (vbe_detect() != 0)
    {
        exports->printf("[VBE] No Bochs/QEMU dispi detected\n");
        return;
    }

    // 2) Discover LFB physical base from PCI (BAR0 of std-VGA).
    uint32_t lfb_phys = vga_get_bar0_phys_base();
    if (lfb_phys == 0)
    {
        exports->printf("[VBE] Failed to obtain LFB physical base from PCI\n");
        return;
    }

    // 3) Program requested mode.
    if (vbe_set_mode(g_req_width, g_req_height, g_req_bpp) != 0)
    {
        exports->printf("[VBE] Failed to set mode %ux%u@%u\n",
                        (unsigned)g_req_width, (unsigned)g_req_height, (unsigned)g_req_bpp);
        return;
    }

    // 4) Read back actual mode and compute pitch.
    {
        uint16_t rx    = vbe_read_reg(VBE_DISPI_INDEX_XRES);
        uint16_t ry    = vbe_read_reg(VBE_DISPI_INDEX_YRES);
        uint16_t rbpp  = vbe_read_reg(VBE_DISPI_INDEX_BPP);
        uint16_t vwid  = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
        uint16_t vhgt  = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);

        if (vwid == 0) { vwid = rx; }
        if (vhgt == 0) { vhgt = ry; }

        // Final sanity (same policy as in vbe_set_mode).
        if (vwid < rx || vwid > 8192) { vwid = rx; }
        if (vhgt < ry || vhgt > 8192) { vhgt = ry; }

        g_mode.width        = (uint32_t)rx;
        g_mode.height       = (uint32_t)ry;
        g_mode.bpp          = (uint32_t)rbpp;
        g_mode.pitch_pixels = (uint32_t)vwid;

        // Bytes per pixel = ceil(bpp/8). For 32-bpp this is 4.
        uint32_t bpp_bytes  = (g_mode.bpp + 7u) / 8u;
        g_mode.pitch_bytes  = g_mode.pitch_pixels * bpp_bytes;
        g_mode.phys_base    = lfb_phys;
    }

    // 5) Hand off to kernel (kernel maps and uses the LFB; expects pitch BYTES).
    if (exports->vbe_register)
    {
        exports->vbe_register(g_mode.phys_base,
                              g_mode.width,
                              g_mode.height,
                              g_mode.bpp,
                              g_mode.pitch_bytes);
    }

#ifdef DIFF_DEBUG
    exports->printf("[VBE] mode=%ux%u@%u pitch(bytes)=%u pitch(px)=%u base=%p\n",
                    (unsigned)g_mode.width, (unsigned)g_mode.height,
                    (unsigned)g_mode.bpp,
                    (unsigned)g_mode.pitch_bytes,
                    (unsigned)g_mode.pitch_pixels,
                    (void *)(uintptr_t)g_mode.phys_base);
#endif

    exports->printf("[DRIVER] VBE Graphics driver installed!\n");
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}

void ddf_driver_exit(void)
{
    // Disable display output on exit.
    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, 0);
    kernel->printf("[DRIVER] VBE Graphics driver uninstalled!\n");
}

// Minimal symbol provider to satisfy tools (only vbe_get_info).
void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name)
{
    (void)module_base;
    (void)header;

    const char target[] = "vbe_get_info";
    const char *p = name;
    const char *q = target;

    while (*p && *q && (*p == *q))
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

