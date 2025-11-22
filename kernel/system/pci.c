#include "pci.h"
#include "io.h"
#include "stdio.h"

// We snapshot every present function we find at boot.
#define PCI_MAX_ENTRIES (PCI_MAX_BUS * PCI_MAX_DEV * PCI_MAX_FUNC)

static pci_device_t g_pci_devices[PCI_MAX_ENTRIES];
static unsigned g_pci_count = 0;

static const char *pci_class_description(uint8_t class_code, uint8_t subclass, uint8_t prog_if)
{
    switch (class_code)
    {
        case 0x00: return "Unclassified device";
        case 0x01:
            switch (subclass)
            {
                case 0x00: return "SCSI storage controller";
                case 0x01: return (prog_if == 0x80) ? "IDE (legacy)" : "IDE storage controller";
                case 0x02: return "Floppy disk controller";
                case 0x03: return "IPI storage controller";
                case 0x04: return "RAID controller";
                case 0x05: return "ATA controller";
                case 0x06: return "Serial ATA controller";
                default: return "Mass storage controller";
            }
        case 0x02:
            switch (subclass)
            {
                case 0x00: return "Ethernet controller";
                case 0x01: return "Token Ring controller";
                case 0x02: return "FDDI controller";
                case 0x03: return "ATM controller";
                default: return "Network controller";
            }
        case 0x03:
            switch (subclass)
            {
                case 0x00: return "VGA compatible controller";
                case 0x01: return "XGA controller";
                case 0x02: return "3D controller";
                default: return "Display controller";
            }
        case 0x04: return "Multimedia controller";
        case 0x05: return "Memory controller";
        case 0x06:
            switch (subclass)
            {
                case 0x00: return "Host bridge";
                case 0x01: return "ISA bridge";
                case 0x02: return "EISA bridge";
                case 0x04: return "PCI-to-PCI bridge";
                case 0x80: return "Other bridge device";
                default: return "Bridge device";
            }
        case 0x07: return "Simple communication controller";
        case 0x08: return "System peripheral";
        case 0x09: return "Input device controller";
        case 0x0A: return "Docking station";
        case 0x0B: return "Processor";
        case 0x0C:
            switch (subclass)
            {
                case 0x00: return "FireWire controller";
                case 0x01: return "ACCESS bus";
                case 0x02: return "SSA";
                case 0x03:
                    switch (prog_if)
                    {
                        case 0x00: return "USB UHCI controller";
                        case 0x10: return "USB OHCI controller";
                        case 0x20: return "USB EHCI controller";
                        case 0x30: return "USB xHCI controller";
                        default: return "USB controller";
                    }
                default: return "Serial bus controller";
            }
        default: return "Unknown class";
    }
}

static void pci_dump_device_list(void)
{
    for (unsigned i = 0; i < g_pci_count; ++i)
    {
        const pci_device_t *dev = &g_pci_devices[i];
        printf("  bus %02u dev %02u func %u | vendor=%04x device=%04x | class=%s (%02x/%02x/%02x) hdr=%02x\n",
               dev->bus,
               dev->device,
               dev->function,
               dev->vendor_id,
               dev->device_id,
               pci_class_description(dev->class_code, dev->subclass, dev->prog_if),
               dev->class_code,
               dev->subclass,
               dev->prog_if,
               dev->header_type);
    }
}

// Legacy Type-1 config space address builder
static uint32_t pci_make_addr(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    return (uint32_t)(0x80000000u
                      | ((uint32_t)bus << 16)
                      | ((uint32_t)dev << 11)
                      | ((uint32_t)func << 8)
                      | (offset & 0xFCu));
}

uint32_t pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    outl(PCI_CONFIG_ADDR, pci_make_addr(bus, dev, func, offset));
    return inl(PCI_CONFIG_DATA);
}

void pci_config_write32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint32_t value)
{
    outl(PCI_CONFIG_ADDR, pci_make_addr(bus, dev, func, offset));
    outl(PCI_CONFIG_DATA, value);
}

static uint16_t pci_config_read16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    uint32_t val = pci_config_read32(bus, dev, func, offset & 0xFC);
    if (offset & 2)
        return (uint16_t)(val >> 16);
    return (uint16_t)(val & 0xFFFF);
}

static uint8_t pci_config_read8(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset)
{
    uint32_t val = pci_config_read32(bus, dev, func, offset & 0xFC);
    return (uint8_t)((val >> ((offset & 3) * 8)) & 0xFF);
}

static void pci_config_write16(uint8_t bus, uint8_t dev, uint8_t func, uint8_t offset, uint16_t value)
{
    uint32_t orig = pci_config_read32(bus, dev, func, offset & 0xFC);
    if (offset & 2)
        orig = (orig & 0x0000FFFFu) | ((uint32_t)value << 16);
    else
        orig = (orig & 0xFFFF0000u) | value;
    pci_config_write32(bus, dev, func, offset & 0xFC, orig);
}

// Stash the function info into our global list
static void pci_record_device(uint8_t bus, uint8_t dev, uint8_t func)
{
    if (g_pci_count >= PCI_MAX_ENTRIES)
        return;

    uint16_t vendor = pci_config_read16(bus, dev, func, PCI_VENDOR_ID);
    if (vendor == 0xFFFF)
        return;

    pci_device_t *entry = &g_pci_devices[g_pci_count++];
    entry->bus = bus;
    entry->device = dev;
    entry->function = func;
    entry->vendor_id = vendor;
    entry->device_id = pci_config_read16(bus, dev, func, PCI_DEVICE_ID);
    entry->class_code = pci_config_read8(bus, dev, func, PCI_CLASS_CODE);
    entry->subclass = pci_config_read8(bus, dev, func, PCI_SUBCLASS);
    entry->prog_if = pci_config_read8(bus, dev, func, PCI_PROG_IF);
    entry->header_type = pci_config_read8(bus, dev, func, PCI_HEADER_TYPE);
}

// Scan a function
static void pci_scan_function(uint8_t bus, uint8_t dev, uint8_t func)
{
    uint16_t vendor = pci_config_read16(bus, dev, func, PCI_VENDOR_ID);
    if (vendor == 0xFFFF)
        return;

    pci_record_device(bus, dev, func);
}

// Scan a device for functions
static void pci_scan_device(uint8_t bus, uint8_t dev)
{
    pci_scan_function(bus, dev, 0);

    uint8_t header = pci_config_read8(bus, dev, 0, PCI_HEADER_TYPE);
    if (!(header & 0x80))
        return;

    for (uint8_t func = 1; func < PCI_MAX_FUNC; ++func)
    {
        pci_scan_function(bus, dev, func);
    }
}

// Step across all 32 devices on a bus
static void pci_scan_bus(uint8_t bus)
{
    for (uint8_t dev = 0; dev < PCI_MAX_DEV; ++dev)
    {
        uint16_t vendor = pci_config_read16(bus, dev, 0, PCI_VENDOR_ID);
        if (vendor == 0xFFFF)
            continue;

        pci_scan_device(bus, dev);
    }
}

void pci_init(void)
{
    g_pci_count = 0;

    for (uint32_t bus = 0; bus < PCI_MAX_BUS; ++bus)
    {
        pci_scan_bus((uint8_t)bus);
    }

    printf("[PCI] Found %u device(s)\n", g_pci_count);
    if (g_pci_count > 0)
    {
        pci_dump_device_list();
    }
}

// Simple enumerator so drivers can look at what we found
void pci_enum_devices(pci_enum_callback_t callback, void *context)
{
    if (!callback)
        return;

    for (unsigned i = 0; i < g_pci_count; ++i)
    {
        callback(&g_pci_devices[i], context);
    }
}

void pci_enable_device(const pci_device_t *dev)
{
    if (!dev)
        return;

    uint16_t command = pci_config_read16(dev->bus, dev->device, dev->function, PCI_COMMAND);
    command |= 0x0007;
    pci_config_write16(dev->bus, dev->device, dev->function, PCI_COMMAND, command);
}

// Get BAR from PCI device
int pci_get_bar(const pci_device_t *dev, uint8_t bar_index, uint32_t *out_base, uint32_t *out_size, int *is_mmio)
{
    if (!dev || bar_index >= 6)
        return -1;

    uint8_t offset = PCI_BAR0 + bar_index * 4;
    uint32_t original = pci_config_read32(dev->bus, dev->device, dev->function, offset);
    if (original == 0)
        return -1;

    pci_config_write32(dev->bus, dev->device, dev->function, offset, 0xFFFFFFFFu);
    uint32_t size_mask = pci_config_read32(dev->bus, dev->device, dev->function, offset);
    pci_config_write32(dev->bus, dev->device, dev->function, offset, original);

    if (original & 0x1)
    {
        if (is_mmio)
            *is_mmio = 0;
        uint32_t base = original & ~0x3u;
        uint32_t size = (~(size_mask & ~0x3u)) + 1u;
        if (out_base)
            *out_base = base;
        if (out_size)
            *out_size = size;
        return 0;
    }
    else
    {
        if (is_mmio)
            *is_mmio = 1;
        uint32_t base = original & ~0xFu;
        uint32_t size = (~(size_mask & ~0xFu)) + 1u;
        if (out_base)
            *out_base = base;
        if (out_size)
            *out_size = size;
        return 0;
    }
}
