#include "drivers/driver.h"
#include "drivers/ddf.h"
#include "drivers/device.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "stdint.h"
#include "pci.h"
#include "system/irqsw.h"

// PCI Identifiers
#define VENDOR_ID   0x10EC      // Realtek
#define DEVICE_ID   0x8139      // RTL8139

// RTL8139 Register Map
// 0x00-0x05    - 6-byte MAC Address
// 0x10-0x1C    - 4 TX Status Registers
// 0x20-0x2C    - 4 TX Address Registers (Physical Address of TX Buffers)
// 0x30         - RX Ring Buffer Physical Address
// 0x37         - Command Register (Enable TX/RX, Reset)
// 0x3C/0x3E    - Interrupt Mask and Status
// 0x40/0x44    - TX and RX Configuration

// RTL8139 Register Offsets
#define REG_MAC0                0x00    // MAC Address bytes 0-3
#define REG_MAC4                0x04    // MAC Address bytes 4-5
#define REG_MAR0                0x08    // Multicast filter bits 0-31
#define REG_MAR4                0x0C    // Multicast filter bits 32-63

#define REG_TXSTATUS0           0x10    // TX Status Descriptor 0
                                        // 4 in total:
                                        // - 0x10
                                        // - 0x14
                                        // - 0x18
                                        // - 0x1C

#define REG_TXADDR0             0x20    // TX Buffer Address 0
                                        // 4 in total:
                                        // - 0x20
                                        // - 0x24
                                        // - 0x28
                                        // - 0x2C

#define REG_RXBUF               0x30    // RX Buffer Physical Address
#define REG_CMD                 0x37    // Command Register

#define REG_CAPR                0x38    // Current Address of Packet Read
                                        // (RX Read Pointer)
#define REG_CBR                 0x3A    // Current Buffer Address
                                        // (RX Write Pointer)

#define REG_IMR                 0x3C    // Interrupt Mask Register
#define REG_ISR                 0x3E    // Interrupt Status Register
#define REG_TCR                 0x40    // Transmit Configuration Register
#define REG_RCR                 0x44    // Receive Configuration Register
#define REG_CONFIG1             0x52    // Configuaration Register 1
#define REG_BMCR                0x62    // Basic Mode Control Register (Physical)

// PCI Configuration
#define PCI_INTERRUPT_LINE      0x3C    // IRQ Line in PCI Config Space

// Command Register bits (REG_CMD)
#define CMD_RESET               0x10    // Software Reset
#define CMD_RX_ENABLE           0x08    // Enable Receiver
#define CMD_TX_ENABLE           0x04    // Enable Transmitter
#define CMD_BUF_EMPTY           0x01    // RX Buffer Empty


// Interrupt Status/Mask bits (REG_ISR / REG_IMR)
#define INT_RX_OK               0x0001  // Packet Received Successfully
#define INT_RX_ERR              0x0002  // Packet Receive Error
#define INT_TX_OK               0x0004  // Packet Transmitted Successfully
#define INT_TX_ERR              0x0008  // Packet Transmit Error
#define INT_RX_OVERFLOW         0x0010  // RX Buffer Overflow
#define INT_LINK_CHANGE         0x0020  // Link Status Changed
#define INT_RX_FIFO_OVER        0x0040  // RX FIFO Overflow
#define INT_TIMEOUT             0x4000  // Cable Length Change Timeout
#define INT_SYSTEM_ERROR        0x8000  // PCI Bus Error


// Receive Configuration Register bits (REG_RCR)
#define RCR_AAP                 0x00000001  // Accept All Packets
#define RCR_APM                 0x00000002  // Accept Physical Match (MAC Address)
#define RCR_AM                  0x00000004  // Accept Multicast
#define RCR_AB                  0x00000008  // Accept Broadcast
#define RCR_WRAP                0x00000080  // Wrap at end of buffer
                                            // (Disable = Overflow to start)
#define RCR_RBLEN_8K            0x00000000  // RX Buffer 8K + 16 bytes
#define RCR_RBLEN_16K           0x00000800  // RX Buffer 16K + 16 bytes
#define RCR_RBLEN_32K           0x00001000  // RX Buffer 32K + 16 bytes
#define RCR_RBLEN_64K           0x00001800  // RX Buffer 64K + 16 bytes


// Transmit Configuration Register bits (REG_TCR)
#define TCR_IFG_NORMAL          0x03000000  // Inter-frame Gap Time (Standard)
#define TCR_MXDMA_2048          0x00000700  // Max DMA Burst Size 2048 bytes


// TX Status Register bits
#define TX_STATUS_OWN           0x00002000  // NIC owns this descriptor
#define TX_STATUS_TUN           0x00004000  // TX Underrun
#define TX_STATUS_TOK           0x00008000  // Transmit OK
#define TX_STATUS_SIZE_MASK     0x00001FFF  // Packet size mask


// RX Status bits (in packet header)
#define RX_STATUS_ROK           0x0001      // Receive OK
#define RX_STATUS_FAE           0x0002      // Frame Alignment Error
#define RX_STATUS_CRC           0x0004      // CRC Error
#define RX_STATUS_LONG          0x0008      // Long Packet (>4KB)
#define RX_STATUS_RUNT          0x0010      // Runt Packet (<64 bytes)
#define RX_STATUS_ISE           0x0020      // Invalid Symbol Error


// RX uses a ring buffer - NIC writes packets sequentially, wraps to start
// 8K is smallest option, 16 bytes for header, 1536 for wrap safety
//
// RX Buffer: 8K + 16 Bytes + 1500 (Wrap Padding)
// RTL8139 can write past end during wrap, we need extra space here
#define RX_BUF_SIZE             (8192+16+1536)
#define RX_BUF_PAGES            3               // 3 Pages = 12Kb

// TX Buffer: 4 Descriptors, each can hold one maximum size packet
#define TX_BUF_SIZE             1536            // Max Eternet Frame
#define TX_BUF_COUNT            4               // 4 TX Descriptors
#define RX_QUEUE_LEN            32

// RTL8139 will be configured dynamically after reading PCI config
// Let's start with IRQ11 is usually the first PCI slot.
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 0;

static kernel_exports_t *kernel = NULL;

typedef struct rtl8139_device
{
    device_t *dev;
    pci_device_t pci;
    uint32_t io_base;
    uint8_t irq;

    // DMA Buffers
    uint32_t rx_buffer_phys;
    uint8_t *rx_buffer;
    uint32_t tx_buffer_phys[TX_BUF_COUNT];
    uint8_t *tx_buffer[TX_BUF_COUNT];

    int tx_current;
    uint16_t rx_read_ptr;
    uint8_t mac_address[6];

    struct
    {
        uint16_t length;
        uint8_t data[TX_BUF_SIZE];
    } rx_queue[RX_QUEUE_LEN];
    uint8_t rx_head;
    uint8_t rx_tail;
    uint8_t rx_count;
    uint32_t rx_dropped;
    uint16_t irqsw_status;
    uint8_t irqsw_pending;

    struct rtl8139_device *next;
} rtl8139_device_t;

static rtl8139_device_t *g_devices = 0;
static rtl8139_device_t g_device_pool[4];
static int g_device_count = 0;

// RX Packet header that the NIC prepends to each packet
typedef struct rx_header
{
    uint16_t status;
    uint16_t length;    // Includes 4 byte CRC
} __attribute__((packed)) rx_header_t;


// Allocate DMA Buffers
static int alloc_dma_buffers(rtl8139_device_t *nic)
{
    if (!nic)
    {
        return -1;
    }

    // Allocate RX Buffer - contiguous pages needed
    nic->rx_buffer_phys = kernel->alloc_phys_pages(RX_BUF_PAGES);

    if (nic->rx_buffer_phys == 0)
    {
        kernel->printf("[DRIVER] RTL8139 - Failed to allocate %d contiguous RX pages!\n", RX_BUF_PAGES);

        return -1;
    }

    // Map the contiguous physical pages to virtual address
    nic->rx_buffer = (uint8_t *)kernel->map_physical(nic->rx_buffer_phys, RX_BUF_PAGES * 4096, 0);

    if (!nic->rx_buffer)
    {
        kernel->printf("[DRIVER] RTL8139 - Failed to map RX buffer!\n");
        kernel->free_phys_pages(nic->rx_buffer_phys, RX_BUF_PAGES);

        return -1;
    }

    // Allocate TX Buffers (1 Page for each should be fine)
    int i;

    for (i = 0; i < TX_BUF_COUNT; i++)
    {
        nic->tx_buffer_phys[i] = kernel->alloc_phys_page();

        if (nic->tx_buffer_phys[i] == 0)
        {
            kernel->printf("[DRIVER] RTL8139 - Failed to allocate TX buffer %d!\n", i);

            goto fail_tx;
        }

        nic->tx_buffer[i] = (uint8_t *)kernel->map_physical(nic->tx_buffer_phys[i], 4096, 0);

        if (!nic->tx_buffer[i])
        {
            kernel->printf("[DRIVER] RTL8139 - Failed to map TX buffer %d!\n", i);
            kernel->free_phys_page(nic->tx_buffer_phys[i]);

            goto fail_tx;
        }
    }

    kernel->printf("[DRIVER] RTL8139 - DMA Buffers Allocated!\n");

    return 0;

fail_tx:
    // Cleanup buffers
    for (int j = 0; j < i; j++)
    {
        kernel->free_phys_page(nic->tx_buffer_phys[j]);
        nic->tx_buffer[j] = NULL;
    }

    kernel->free_phys_pages(nic->rx_buffer_phys, RX_BUF_PAGES);
    nic->rx_buffer = NULL;

    return -1;
}

// Free DMA Buffers
static void free_dma_buffers(rtl8139_device_t *nic)
{
    if (!nic)
    {
        return;
    }

    // Free TX buffers
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        if (nic->tx_buffer_phys[i])
        {
            kernel->free_phys_page(nic->tx_buffer_phys[i]);
            nic->tx_buffer_phys[i] = 0;
            nic->tx_buffer[i] = NULL;
        }
    }

    // Free RX buffer
    if (nic->rx_buffer_phys)
    {
        kernel->free_phys_pages(nic->rx_buffer_phys, RX_BUF_PAGES);
        nic->rx_buffer_phys = 0;
        nic->rx_buffer = NULL;
    }

    kernel->printf("[DRIVER] RTL8139 - DMA Buffers freed!\n");
}

// Read MAC address from the NIC
static void read_mac_address(rtl8139_device_t *nic)
{
    uint32_t mac0 = kernel->inl(nic->io_base + REG_MAC0);
    uint16_t mac4 = kernel->inw(nic->io_base + REG_MAC4);

    nic->mac_address[0] = (mac0 >> 0) & 0xFF;
    nic->mac_address[1] = (mac0 >> 8) & 0xFF;
    nic->mac_address[2] = (mac0 >> 16) & 0xFF;
    nic->mac_address[3] = (mac0 >> 24) & 0xFF;
    nic->mac_address[4] = (mac4 >> 0) & 0xFF;
    nic->mac_address[5] = (mac4 >> 8) & 0xFF;

    kernel->printf("[DRIVER] RTL8139 - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   nic->mac_address[0], nic->mac_address[1], nic->mac_address[2],
                   nic->mac_address[3], nic->mac_address[4], nic->mac_address[5]);
}

// Init RX
static void init_rx(rtl8139_device_t *nic)
{
    // Zero the RX buffer
    for (int i = 0; i < RX_BUF_SIZE; i++)
    {
        nic->rx_buffer[i] = 0;
    }

    // Tell NIC where our RX buffer is located
    kernel->outl(nic->io_base + REG_RXBUF, nic->rx_buffer_phys);

    // Configure receiver - accept our MAC, broadcast, and multicast
    uint32_t rcr = RCR_APM | RCR_AB | RCR_AM | RCR_RBLEN_8K;
    kernel->outl(nic->io_base + REG_RCR, rcr);

    // Reset read pointer - hardware quirk requires starting at 0xFFF0
    nic->rx_read_ptr = 0;
    kernel->outw(nic->io_base + REG_CAPR, 0xFFF0);

    kernel->printf("[DRIVER] RTL8139 - RX Ready!\n");
}

// Init TX
static void init_tx(rtl8139_device_t *nic)
{
    // Zero the TX buffers and set their addresses
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        for (int j = 0; j < TX_BUF_SIZE; j++)
        {
            nic->tx_buffer[i][j] = 0;
        }

        // Tell NIC each TX buffers physical address
        kernel->outl(nic->io_base + REG_TXADDR0 + (i * 4), nic->tx_buffer_phys[i]);
    }

    // Configure transmitter - normal inter-frame gap, 2048 byte DMA burst
    uint32_t tcr = TCR_IFG_NORMAL | TCR_MXDMA_2048;
    kernel->outl(nic->io_base + REG_TCR, tcr);

    nic->tx_current = 0;

    kernel->printf("[DRIVER] RTL8139 - TX Ready!\n");
}

// Enable the NIC (RX and TX)
static void device_enable(rtl8139_device_t *nic)
{
    kernel->outb(nic->io_base + REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

    kernel->printf("[DRIVER] RTL8139 - RX/TX Enabled!\n");
}

// Enable interrupts on the NIC
static void enable_interrupts(rtl8139_device_t *nic)
{
    // Enable the interrupts we care about
    uint16_t imr = INT_RX_OK | INT_TX_OK | INT_RX_ERR | INT_TX_ERR | INT_RX_OVERFLOW;
    kernel->outw(nic->io_base + REG_IMR, imr);

    // Unmask IRQ at the PIC
    kernel->pic_clear_mask(nic->irq);

    kernel->printf("[DRIVER] RTL8139 - Interrupts Enabled, IRQ=%d\n", nic->irq);
}

// Handle received packets
static void handle_rx(rtl8139_device_t *nic)
{
    // Process all available packets
    while (!(kernel->inb(nic->io_base + REG_CMD) & CMD_BUF_EMPTY))
    {
        // Get packet header from current position
        rx_header_t *header = (rx_header_t *)(nic->rx_buffer + nic->rx_read_ptr);

        uint16_t status = header->status;
        uint16_t length = header->length;

        // Check for valid packet
        if (!(status & RX_STATUS_ROK))
        {
            kernel->printf("[DRIVER] RTL8139 - RX bad packet, status=0x%x\n", status);

            break;
        }

        // Sanity check the length
        if (length > 1518 + 4 || length < 8)
        {
            kernel->printf("[DRIVER] RTL8139 - RX bad length=%d\n", length);

            break;
        }

        // Packet data starts after 4 byte header
        uint8_t *packet_data = nic->rx_buffer + nic->rx_read_ptr + 4;
        uint16_t packet_len = length - 4;   // Exclude CRC

        if (packet_len <= TX_BUF_SIZE)
        {
            if (nic->rx_count < RX_QUEUE_LEN)
            {
                uint8_t slot = nic->rx_tail;
                nic->rx_queue[slot].length = packet_len;
                for (uint16_t i = 0; i < packet_len; i++)
                {
                    nic->rx_queue[slot].data[i] = packet_data[i];
                }
                nic->rx_tail = (uint8_t)((nic->rx_tail + 1) % RX_QUEUE_LEN);
                nic->rx_count++;
            }
            else
            {
                nic->rx_dropped++;
            }
        }
        else
        {
            nic->rx_dropped++;
        }

        // Advance read pointer - must be 4 byte aligned
        nic->rx_read_ptr = (nic->rx_read_ptr + 4 + length + 3) & ~3;
        nic->rx_read_ptr %= 8192;    // Wrap at 8K buffer size

        // Update CAPR - hardware quirk requires subtracting 16
        kernel->outw(nic->io_base + REG_CAPR, nic->rx_read_ptr - 16);
    }
}

// Handle TX completion
static void handle_tx(rtl8139_device_t *nic)
{
    // Check all 4 TX descriptors for completion
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        uint32_t status = kernel->inl(nic->io_base + REG_TXSTATUS0 + (i * 4));

        if (status & TX_STATUS_TOK)
        {
            // Packet sent successfully
            // Status is cleared when we write a new packet
        }

        if (status & TX_STATUS_TUN)
        {
            kernel->printf("[DRIVER] RTL8139 - TX underrun on descriptor %d\n", i);
        }
    }
}

// Send a packet
// Returns 0 on success, -1 on failure
static int rtl8139_send(rtl8139_device_t *nic, const uint8_t *data, uint16_t length)
{
    if (!data || length == 0 || length > TX_BUF_SIZE)
    {
        return -1;
    }

    // Wait for current descriptor to be free
    uint32_t status = kernel->inl(nic->io_base + REG_TXSTATUS0 + (nic->tx_current * 4));

    if (status & TX_STATUS_OWN)
    {
        // NIC still owns this buffer
        kernel->printf("[DRIVER] RTL8139 - TX buffer %d busy\n", nic->tx_current);

        return -1;
    }

    // Copy packet data to TX buffer
    for (uint16_t i = 0; i < length; i++)
    {
        nic->tx_buffer[nic->tx_current][i] = data[i];
    }

    // Tell the NIC to send - write length to status register
    // Bit 13 (OWN) must be 0, bits 0-12 are the size
    kernel->outl(nic->io_base + REG_TXSTATUS0 + (nic->tx_current * 4), length);

    // Move to next descriptor
    nic->tx_current = (nic->tx_current + 1) % TX_BUF_COUNT;

    return 0;
}

// PCI scan callback
static void pci_scan_callback(const pci_device_t *dev, void *ctx)
{
    (void)ctx;

    if (dev->vendor_id == VENDOR_ID && dev->device_id == DEVICE_ID)
    {
        if (g_device_count >= 4)
        {
            kernel->printf("[DRIVER] RTL8139 - Max devices reached, skipping %d:%d.%d\n", dev->bus, dev->device, dev->function);

            return;
        }

        rtl8139_device_t *nic = &g_device_pool[g_device_count++];
        nic->dev = 0;
        nic->pci = *dev;
        nic->io_base = 0;
        nic->irq = 0;
        nic->rx_buffer_phys = 0;
        nic->rx_buffer = 0;
        for (int i = 0; i < TX_BUF_COUNT; i++)
        {
            nic->tx_buffer_phys[i] = 0;
            nic->tx_buffer[i] = 0;
        }
        nic->tx_current = 0;
        nic->rx_read_ptr = 0;
        for (int i = 0; i < 6; i++)
        {
            nic->mac_address[i] = 0;
        }
        nic->rx_head = 0;
        nic->rx_tail = 0;
        nic->rx_count = 0;
        nic->rx_dropped = 0;
        nic->irqsw_status = 0;
        nic->irqsw_pending = 0;
        nic->next = g_devices;
        g_devices = nic;

        kernel->printf("[DRIVER] RTL8139 Network Card found at PCI %d:%d.%d\n", dev->bus, dev->device, dev->function);
    }
}

// Reset Device
// - Write CMD_RESET to command register
// - Poll until the chip clears the bit
// - All registers return to default values
static void device_reset(rtl8139_device_t *nic)
{
    // Send reset command
    kernel->outb(nic->io_base + REG_CMD, CMD_RESET);

    // Wait for reset to complete, bit should clear itself
    int timeout = 1000;

    while ((kernel->inb(nic->io_base + REG_CMD) & CMD_RESET) && timeout > 0)
    {
        timeout--;
    }

    if (timeout == 0)
    {
        kernel->printf("[DRIVER] RTL8139 Reset Timeout!\n");
    }
    else
    {
        kernel->printf("[DRIVER] RTL8139 Reset Completed!\n");
    }
}

// Device operations
static int nic_dev_get_mac(device_t *dev, uint8_t mac[6])
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic)
    {
        return -1;
    }

    for (int i = 0; i < 6; i++)
    {
        mac[i] = nic->mac_address[i];
    }

    return 0;
}

static int nic_dev_send_packet(device_t *dev, const void *data, uint16_t length)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    return rtl8139_send(nic, (const uint8_t *)data, length);
}

static int nic_dev_receive_packet(device_t *dev, void *buffer, uint16_t buf_size)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic || !buffer || buf_size == 0)
    {
        return -1;
    }

    if (nic->rx_count == 0)
    {
        return 0;
    }

    uint8_t slot = nic->rx_head;
    uint16_t length = nic->rx_queue[slot].length;

    if (length > buf_size)
    {
        return -1;
    }

    for (uint16_t i = 0; i < length; i++)
    {
        ((uint8_t *)buffer)[i] = nic->rx_queue[slot].data[i];
    }

    nic->rx_head = (uint8_t)((nic->rx_head + 1) % RX_QUEUE_LEN);
    nic->rx_count--;

    return (int)length;
}

static int nic_dev_packets_available(device_t *dev)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic)
    {
        return 0;
    }

    return nic->rx_count;
}

static int nic_dev_set_promiscuous(device_t *dev, int enabled)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic)
    {
        return -1;
    }

    uint32_t rcr = kernel->inl(nic->io_base + REG_RCR);

    if (enabled)
    {
        rcr |= RCR_AAP;
    }
    else
    {
        rcr &= ~RCR_AAP;
    }

    kernel->outl(nic->io_base + REG_RCR, rcr);

    return 0;
}

static int nic_dev_get_link_status(device_t *dev)
{
    (void)dev;

    return 1;
}

static uint32_t nic_dev_get_speed(device_t *dev)
{
    (void)dev;

    return 100;  // RTL8139 is 100 Mbps
}

static network_device_t g_nic_ops =
{
    .get_mac = nic_dev_get_mac,
    .send_packet = nic_dev_send_packet,
    .receive_packet = nic_dev_receive_packet,
    .packets_available = nic_dev_packets_available,
    .get_link_status = nic_dev_get_link_status,
    .get_speed = nic_dev_get_speed,
    .set_promiscuous = nic_dev_set_promiscuous,
    .set_multicast = 0,
};

static void rtl8139_irq_handler(unsigned irq, void *context);
static void rtl8139_irqsw_handler(void *context);

static int rtl8139_stop(device_t *dev)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic)
    {
        return -1;
    }

    // Disable interrupts and RX/TX
    kernel->outw(nic->io_base + REG_IMR, 0);
    kernel->outb(nic->io_base + REG_CMD, 0);

    return 0;
}

static void rtl8139_cleanup(device_t *dev)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)dev->private_data;

    if (!nic)
    {
        return;
    }

    kernel->irq_unregister_handler(nic->irq, rtl8139_irq_handler, nic);
    free_dma_buffers(nic);
    nic->dev = 0;
}

static void rtl8139_irq_handler(unsigned irq, void *context)
{
    (void)irq;

    rtl8139_device_t *nic = (rtl8139_device_t *)context;

    if (!nic)
    {
        return;
    }

    // Read interrupt status
    uint16_t status = kernel->inw(nic->io_base + REG_ISR);

    if (status == 0)
    {
        return;     // Not our interrupt
    }

    nic->irqsw_status |= status;

    if (!nic->irqsw_pending && kernel->irqsw_queue)
    {
        nic->irqsw_pending = 1;
        kernel->irqsw_queue(rtl8139_irqsw_handler, nic);
    }

    kernel->outw(nic->io_base + REG_ISR, status);
}

static void rtl8139_irqsw_handler(void *context)
{
    rtl8139_device_t *nic = (rtl8139_device_t *)context;

    if (!nic)
    {
        return;
    }

    for (;;)
    {
        uint16_t status = nic->irqsw_status;
        nic->irqsw_status = 0;

        if (status == 0)
        {
            break;
        }

        if (status & INT_RX_OK)
        {
            handle_rx(nic);
        }

        if (status & INT_TX_OK)
        {
            handle_tx(nic);
        }

        if (status & INT_RX_ERR)
        {
            kernel->printf("[DRIVER] RTL8139 - RX error\n");
        }

        if (status & INT_TX_ERR)
        {
            kernel->printf("[DRIVER] RTL8139 - TX error\n");
        }

        if (status & INT_RX_OVERFLOW)
        {
            kernel->printf("[DRIVER] RTL8139 - RX overflow, resetting RX\n");

            kernel->outb(nic->io_base + REG_CMD, CMD_TX_ENABLE);
            kernel->outb(nic->io_base + REG_CMD, CMD_TX_ENABLE | CMD_RX_ENABLE);
        }
    }

    nic->irqsw_pending = 0;

    if (nic->irqsw_status != 0 && kernel->irqsw_queue)
    {
        nic->irqsw_pending = 1;
        kernel->irqsw_queue(rtl8139_irqsw_handler, nic);
    }
}

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // Scan for RTL8139 Network Card
    kernel->pci_enum_devices(pci_scan_callback, NULL);

    if (!g_devices)
    {
        kernel->printf("[DRIVER] Could not find a RTL8139 device!\n");

        return;
    }

    for (rtl8139_device_t *nic = g_devices; nic; nic = nic->next)
    {
        // Enable device
        kernel->pci_enable_device(&nic->pci);

        uint32_t bar_size;
        int is_mmio;

        // Get I/O base from BAR0
        if (kernel->pci_get_bar(&nic->pci, 0, &nic->io_base, &bar_size, &is_mmio) < 0)
        {
            kernel->printf("[DRIVER] Could not find BAR0 for RTL8139 device!\n");

            continue;
        }

        // Read IRQ from PCI config
        uint32_t irq_reg = kernel->pci_config_read32(nic->pci.bus, nic->pci.device, nic->pci.function, PCI_INTERRUPT_LINE);
        nic->irq = (uint8_t)(irq_reg & 0xFF);

        kernel->printf("[DRIVER] RTL8139 - I/O base=0x%x, IRQ=%d\n", nic->io_base, nic->irq);

        // Allocate DMA buffers
        if (alloc_dma_buffers(nic) < 0)
        {
            continue;
        }

        // Reset the chip
        device_reset(nic);

        // Read MAC address
        read_mac_address(nic);

        // Initialize RX and TX
        init_rx(nic);
        init_tx(nic);

        // Enable RX/TX
        device_enable(nic);

        // Enable interrupts
        enable_interrupts(nic);

        // Register IRQ handler
        kernel->irq_register_handler(nic->irq, rtl8139_irq_handler, nic);

        // Register device
        nic->dev = kernel->device_register(DEVICE_CLASS_NETWORK, "rtl8139", &g_nic_ops);
        if (nic->dev)
        {
            nic->dev->bus_type = BUS_TYPE_PCI;
            nic->dev->vendor_id = VENDOR_ID;
            nic->dev->device_id = DEVICE_ID;
            nic->dev->irq = nic->irq;
            nic->dev->io_base = nic->io_base;
            nic->dev->private_data = nic;
            nic->dev->stop = rtl8139_stop;
            nic->dev->cleanup = rtl8139_cleanup;
            kernel->strlcpy(nic->dev->description, "Realtek RTL8139 Fast Ethernet", sizeof(nic->dev->description));
        }
    }

    kernel->printf("[DRIVER] RTL8139 Network Driver Installed!\n");
}

void ddf_driver_exit(void)
{
    for (rtl8139_device_t *nic = g_devices; nic; nic = nic->next)
    {
        if (nic->dev)
        {
            kernel->device_unregister(nic->dev);
            nic->dev = 0;
        }
    }

    g_devices = 0;
    g_device_count = 0;

    kernel->printf("[DRIVER] RTL8139 Network Driver Uninstalled!\n");
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;
}
