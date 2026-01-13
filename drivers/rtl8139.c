#include "drivers/driver.h"
#include "drivers/ddf.h"
#include "drivers/device.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "stdint.h"
#include "pci.h"
#include "system/irqsw.h"

// RTL8139 PCI identifiers
#define RTL_VENDOR_ID       0x10EC
#define RTL_DEVICE_ID       0x8139

// Register offsets
#define REG_MAC0            0x00    // MAC address bytes 0-3
#define REG_MAC4            0x04    // MAC address bytes 4-5
#define REG_TX_STATUS0      0x10    // TX descriptor 0 status
#define REG_TX_ADDR0        0x20    // TX descriptor 0 address
#define REG_RX_BUF          0x30    // RX buffer physical address
#define REG_CMD             0x37    // Command register
#define REG_CAPR            0x38    // Current address of packet read
#define REG_CBR             0x3A    // Current buffer address (write pointer)
#define REG_IMR             0x3C    // Interrupt mask
#define REG_ISR             0x3E    // Interrupt status
#define REG_TX_CONFIG       0x40    // TX configuration
#define REG_RX_CONFIG       0x44    // RX configuration
#define REG_CONFIG1         0x52    // Configuration register 1

// Command register bits
#define CMD_RESET           0x10
#define CMD_RX_ENABLE       0x08
#define CMD_TX_ENABLE       0x04
#define CMD_BUF_EMPTY       0x01

// Interrupt bits
#define INT_RX_OK           0x0001
#define INT_RX_ERR          0x0002
#define INT_TX_OK           0x0004
#define INT_TX_ERR          0x0008
#define INT_RX_OVERFLOW     0x0010

// TX status bits
#define TX_OWN              0x2000
#define TX_TOK              0x8000

// RX status bits
#define RX_ROK              0x0001

// RX config bits
#define RCR_AAP             0x01    // Accept all packets
#define RCR_APM             0x02    // Accept physical match
#define RCR_AM              0x04    // Accept multicast
#define RCR_AB              0x08    // Accept broadcast
#define RCR_WRAP            0x80    // Wrap mode
#define RCR_RBLEN_8K        0x0000
#define RCR_RBLEN_16K       0x0800
#define RCR_RBLEN_32K       0x1000
#define RCR_RBLEN_64K       0x1800

// TX config bits
#define TCR_IFG_NORMAL      0x03000000
#define TCR_MXDMA_2048      0x00000700

// Buffer sizes
#define RX_BUF_SIZE         8192
#define RX_BUF_PAD          16
#define RX_BUF_WRAP         1536
#define RX_BUF_TOTAL        (RX_BUF_SIZE + RX_BUF_PAD + RX_BUF_WRAP)
#define TX_BUF_SIZE         1536
#define TX_DESC_COUNT       4

// Software RX queue
#define RX_QUEUE_SIZE       16

__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static kernel_exports_t *kernel = NULL;

// RX packet header from hardware
typedef struct rx_header
{
    uint16_t status;
    uint16_t length;
} __attribute__((packed)) rx_header_t;

// Queued packet
typedef struct rx_packet
{
    uint16_t length;
    uint8_t data[TX_BUF_SIZE];
} rx_packet_t;

// Device state
typedef struct rtl_device
{
    pci_device_t pci;
    uint32_t io_base;
    uint8_t irq;
    uint8_t mac[6];

    // RX state
    uint32_t rx_phys;
    uint8_t *rx_buffer;
    uint32_t rx_offset;

    // TX state
    uint32_t tx_phys[TX_DESC_COUNT];
    uint8_t *tx_buffer[TX_DESC_COUNT];
    int tx_next;

    // Software queue
    rx_packet_t rx_queue[RX_QUEUE_SIZE];
    int rx_head;
    int rx_tail;
    int rx_count;

    // IRQ handling
    uint16_t pending_status;
    int irq_queued;

    device_t *dev;
} rtl_device_t;

static rtl_device_t g_device;
static int g_found = 0;

// Wait for reset to complete
static int rtl_reset(rtl_device_t *rtl)
{
    kernel->outb(rtl->io_base + REG_CMD, CMD_RESET);

    for (int i = 0; i < 1000; i++)
    {
        if ((kernel->inb(rtl->io_base + REG_CMD) & CMD_RESET) == 0)
        {
            return 0;
        }
    }

    return -1;
}

// Read MAC address from EEPROM
static void rtl_read_mac(rtl_device_t *rtl)
{
    uint32_t mac_low = kernel->inl(rtl->io_base + REG_MAC0);
    uint16_t mac_high = kernel->inw(rtl->io_base + REG_MAC4);

    rtl->mac[0] = (mac_low >> 0) & 0xFF;
    rtl->mac[1] = (mac_low >> 8) & 0xFF;
    rtl->mac[2] = (mac_low >> 16) & 0xFF;
    rtl->mac[3] = (mac_low >> 24) & 0xFF;
    rtl->mac[4] = (mac_high >> 0) & 0xFF;
    rtl->mac[5] = (mac_high >> 8) & 0xFF;
}

// Allocate DMA buffers
static int rtl_alloc_buffers(rtl_device_t *rtl)
{
    // RX buffer needs 3 contiguous pages
    int rx_pages = (RX_BUF_TOTAL + 4095) / 4096;
    rtl->rx_phys = kernel->alloc_phys_pages(rx_pages);

    if (rtl->rx_phys == 0)
    {
        return -1;
    }

    rtl->rx_buffer = kernel->map_physical(rtl->rx_phys, rx_pages * 4096, 0);

    if (!rtl->rx_buffer)
    {
        kernel->free_phys_pages(rtl->rx_phys, rx_pages);

        return -1;
    }

    // TX buffers - one page each
    for (int i = 0; i < TX_DESC_COUNT; i++)
    {
        rtl->tx_phys[i] = kernel->alloc_phys_page();

        if (rtl->tx_phys[i] == 0)
        {
            // Cleanup on failure
            for (int j = 0; j < i; j++)
            {
                kernel->free_phys_page(rtl->tx_phys[j]);
            }

            kernel->free_phys_pages(rtl->rx_phys, rx_pages);

            return -1;
        }

        rtl->tx_buffer[i] = kernel->map_physical(rtl->tx_phys[i], 4096, 0);
    }

    return 0;
}

// Initialize hardware
static void rtl_hw_init(rtl_device_t *rtl)
{
    // Set RX buffer address
    kernel->outl(rtl->io_base + REG_RX_BUF, rtl->rx_phys);

    // Set TX buffer addresses
    for (int i = 0; i < TX_DESC_COUNT; i++)
    {
        kernel->outl(rtl->io_base + REG_TX_ADDR0 + i * 4, rtl->tx_phys[i]);
    }

    // Configure RX - accept broadcast, multicast, and our MAC
    uint32_t rx_config = RCR_APM | RCR_AB | RCR_AM | RCR_RBLEN_8K;
    kernel->outl(rtl->io_base + REG_RX_CONFIG, rx_config);

    // Configure TX
    uint32_t tx_config = TCR_IFG_NORMAL | TCR_MXDMA_2048;
    kernel->outl(rtl->io_base + REG_TX_CONFIG, tx_config);

    // Reset read pointer
    rtl->rx_offset = 0;
    kernel->outw(rtl->io_base + REG_CAPR, 0xFFF0);

    // Enable RX and TX
    kernel->outb(rtl->io_base + REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

    // Enable interrupts
    uint16_t imr = INT_RX_OK | INT_TX_OK | INT_RX_ERR | INT_TX_ERR | INT_RX_OVERFLOW;
    kernel->outw(rtl->io_base + REG_IMR, imr);

    // Unmask IRQ
    kernel->pic_clear_mask(rtl->irq);
}

// Process received packets from hardware buffer into software queue
static void rtl_process_rx(rtl_device_t *rtl)
{
    while ((kernel->inb(rtl->io_base + REG_CMD) & CMD_BUF_EMPTY) == 0)
    {
        uint32_t offset = rtl->rx_offset % RX_BUF_SIZE;
        rx_header_t *header = (rx_header_t *)(rtl->rx_buffer + offset);

        uint16_t status = header->status;
        uint16_t length = header->length;

        // Check valid packet
        if ((status & RX_ROK) == 0)
        {
            kernel->printf("[RTL] RX error status=0x%04x\n", status);

            break;
        }

        // Sanity check length
        if (length < 8 || length > 1522)
        {
            kernel->printf("[RTL] RX bad length=%u\n", length);

            break;
        }

        // Queue packet if space available
        uint16_t data_len = length - 4;  // Remove CRC

        if (rtl->rx_count < RX_QUEUE_SIZE && data_len <= TX_BUF_SIZE)
        {
            rx_packet_t *pkt = &rtl->rx_queue[rtl->rx_tail];
            pkt->length = data_len;

            // Copy data handling wrap
            uint32_t data_start = (offset + 4) % RX_BUF_SIZE;

            for (uint16_t i = 0; i < data_len; i++)
            {
                pkt->data[i] = rtl->rx_buffer[(data_start + i) % RX_BUF_SIZE];
            }

            rtl->rx_tail = (rtl->rx_tail + 1) % RX_QUEUE_SIZE;
            rtl->rx_count++;
        }

        // Advance hardware pointer (4-byte aligned)
        rtl->rx_offset = (rtl->rx_offset + length + 4 + 3) & ~3;

        // Update CAPR (hardware quirk: subtract 16)
        kernel->outw(rtl->io_base + REG_CAPR, (rtl->rx_offset - 16) & 0xFFFF);
    }
}

// IRQ handler - runs in interrupt context
static void rtl_irq_handler(unsigned irq, void *context);
static void rtl_irq_worker(void *context);

static void rtl_irq_handler(unsigned irq, void *context)
{
    (void)irq;
    rtl_device_t *rtl = (rtl_device_t *)context;

    uint16_t status = kernel->inw(rtl->io_base + REG_ISR);

    if (status == 0)
    {
        return;
    }

    // Acknowledge interrupts
    kernel->outw(rtl->io_base + REG_ISR, status);

    // Accumulate status for worker
    rtl->pending_status |= status;

    if (!rtl->irq_queued)
    {
        rtl->irq_queued = 1;
        kernel->irqsw_queue(rtl_irq_worker, rtl);
    }
}

// IRQ worker - runs in task context
static void rtl_irq_worker(void *context)
{
    rtl_device_t *rtl = (rtl_device_t *)context;

    uint16_t status = rtl->pending_status;
    rtl->pending_status = 0;
    rtl->irq_queued = 0;

    if (status & (INT_RX_OK | INT_RX_ERR | INT_RX_OVERFLOW))
    {
        rtl_process_rx(rtl);
    }

    if (status & INT_RX_OVERFLOW)
    {
        kernel->printf("[RTL] RX overflow, resetting\n");
        kernel->outb(rtl->io_base + REG_CMD, CMD_TX_ENABLE);
        kernel->outb(rtl->io_base + REG_CMD, CMD_TX_ENABLE | CMD_RX_ENABLE);
    }
}

// Network device operations
static int rtl_get_mac(device_t *dev, uint8_t mac[6])
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    for (int i = 0; i < 6; i++)
    {
        mac[i] = rtl->mac[i];
    }

    return 0;
}

static int rtl_send_packet(device_t *dev, const void *data, uint16_t length)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    if (!data || length == 0 || length > TX_BUF_SIZE)
    {
        return -1;
    }

    // Find a free descriptor
    int desc = rtl->tx_next;
    uint32_t status = kernel->inl(rtl->io_base + REG_TX_STATUS0 + desc * 4);

    // If not ready, wait briefly or force
    if (status & TX_OWN)
    {
        // Try next descriptor
        for (int i = 0; i < TX_DESC_COUNT; i++)
        {
            int try_desc = (rtl->tx_next + i) % TX_DESC_COUNT;
            status = kernel->inl(rtl->io_base + REG_TX_STATUS0 + try_desc * 4);

            if ((status & TX_OWN) == 0)
            {
                desc = try_desc;

                break;
            }
        }
    }

    // Copy packet data
    uint8_t *buf = rtl->tx_buffer[desc];

    for (uint16_t i = 0; i < length; i++)
    {
        buf[i] = ((const uint8_t *)data)[i];
    }

    // Start transmission - write length to status register
    kernel->outl(rtl->io_base + REG_TX_STATUS0 + desc * 4, length);

    // Advance to next descriptor
    rtl->tx_next = (desc + 1) % TX_DESC_COUNT;

    return 0;
}

static int rtl_receive_packet(device_t *dev, void *buffer, uint16_t buf_size)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    if (rtl->rx_count == 0)
    {
        return 0;
    }

    rx_packet_t *pkt = &rtl->rx_queue[rtl->rx_head];

    if (pkt->length > buf_size)
    {
        return -1;
    }

    for (uint16_t i = 0; i < pkt->length; i++)
    {
        ((uint8_t *)buffer)[i] = pkt->data[i];
    }

    int length = pkt->length;

    rtl->rx_head = (rtl->rx_head + 1) % RX_QUEUE_SIZE;
    rtl->rx_count--;

    return length;
}

static int rtl_packets_available(device_t *dev)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    // Try to receive more packets before reporting count
    if (rtl->rx_count == 0)
    {
        rtl_process_rx(rtl);
    }

    return rtl->rx_count;
}

static int rtl_get_link_status(device_t *dev)
{
    (void)dev;

    return 1;
}

static uint32_t rtl_get_speed(device_t *dev)
{
    (void)dev;

    return 100;
}

static int rtl_set_promiscuous(device_t *dev, int enabled)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    uint32_t rcr = kernel->inl(rtl->io_base + REG_RX_CONFIG);

    if (enabled)
    {
        rcr |= RCR_AAP;
    }
    else
    {
        rcr &= ~RCR_AAP;
    }

    kernel->outl(rtl->io_base + REG_RX_CONFIG, rcr);

    return 0;
}

static network_device_t g_rtl_ops =
{
    .get_mac = rtl_get_mac,
    .send_packet = rtl_send_packet,
    .receive_packet = rtl_receive_packet,
    .packets_available = rtl_packets_available,
    .get_link_status = rtl_get_link_status,
    .get_speed = rtl_get_speed,
    .set_promiscuous = rtl_set_promiscuous,
    .set_multicast = NULL
};

// PCI scan callback
static void rtl_pci_callback(const pci_device_t *dev, void *ctx)
{
    (void)ctx;

    if (dev->vendor_id == RTL_VENDOR_ID && dev->device_id == RTL_DEVICE_ID)
    {
        if (!g_found)
        {
            g_device.pci = *dev;
            g_found = 1;
            kernel->printf("[RTL] Found RTL8139 at PCI %d:%d.%d\n",
                dev->bus, dev->device, dev->function);
        }
    }
}

static int rtl_stop(device_t *dev)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    kernel->outw(rtl->io_base + REG_IMR, 0);
    kernel->outb(rtl->io_base + REG_CMD, 0);

    return 0;
}

static void rtl_cleanup(device_t *dev)
{
    rtl_device_t *rtl = (rtl_device_t *)dev->private_data;

    kernel->irq_unregister_handler(rtl->irq, rtl_irq_handler, rtl);
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // Find RTL8139
    kernel->pci_enum_devices(rtl_pci_callback, NULL);

    if (!g_found)
    {
        kernel->printf("[RTL] No RTL8139 found\n");

        return;
    }

    rtl_device_t *rtl = &g_device;

    // Enable PCI device
    kernel->pci_enable_device(&rtl->pci);

    // Get I/O base
    uint32_t bar_size;
    int is_mmio;

    if (kernel->pci_get_bar(&rtl->pci, 0, &rtl->io_base, &bar_size, &is_mmio) < 0)
    {
        kernel->printf("[RTL] Failed to get BAR0\n");

        return;
    }

    // Get IRQ
    uint32_t irq_reg = kernel->pci_config_read32(rtl->pci.bus, rtl->pci.device,
        rtl->pci.function, 0x3C);
    rtl->irq = irq_reg & 0xFF;

    kernel->printf("[RTL] I/O base=0x%x IRQ=%d\n", rtl->io_base, rtl->irq);

    // Allocate DMA buffers
    if (rtl_alloc_buffers(rtl) < 0)
    {
        kernel->printf("[RTL] Failed to allocate buffers\n");

        return;
    }

    // Reset chip
    if (rtl_reset(rtl) < 0)
    {
        kernel->printf("[RTL] Reset timeout\n");

        return;
    }

    // Read MAC
    rtl_read_mac(rtl);
    kernel->printf("[RTL] MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        rtl->mac[0], rtl->mac[1], rtl->mac[2],
        rtl->mac[3], rtl->mac[4], rtl->mac[5]);

    // Initialize hardware
    rtl_hw_init(rtl);

    // Register IRQ handler
    kernel->irq_register_handler(rtl->irq, rtl_irq_handler, rtl);

    // Register device
    rtl->dev = kernel->device_register(DEVICE_CLASS_NETWORK, "rtl8139", &g_rtl_ops);

    if (rtl->dev)
    {
        rtl->dev->bus_type = BUS_TYPE_PCI;
        rtl->dev->vendor_id = RTL_VENDOR_ID;
        rtl->dev->device_id = RTL_DEVICE_ID;
        rtl->dev->irq = rtl->irq;
        rtl->dev->io_base = rtl->io_base;
        rtl->dev->private_data = rtl;
        rtl->dev->stop = rtl_stop;
        rtl->dev->cleanup = rtl_cleanup;
        kernel->strlcpy(rtl->dev->description, "Realtek RTL8139 NIC",
            sizeof(rtl->dev->description));
    }

    kernel->printf("[RTL] Driver loaded\n");
}

void ddf_driver_exit(void)
{
    if (g_device.dev)
    {
        kernel->device_unregister(g_device.dev);
        g_device.dev = NULL;
    }

    kernel->printf("[RTL] Driver unloaded\n");
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
