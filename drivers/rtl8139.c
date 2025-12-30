#include "drivers/driver.h"
#include "drivers/ddf.h"
#include "io.h"
#include "stdio.h"
#include "stddef.h"
#include "stdint.h"
#include "pci.h"

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

// RTL8139 will be configured dynamically after reading PCI config
// Let's start with IRQ11 is usually the first PCI slot.
__attribute__((section(".ddf_meta"), used))
volatile unsigned int ddf_irq_number = 11;

static kernel_exports_t *kernel = NULL;

static pci_device_t device;
static int device_found = 0;
static uint32_t io_base = 0;    // I/O Port Base Address
static uint8_t device_irq = 0;  // IRQ from PCI config

// DMA Buffers
static uint32_t rx_buffer_phys;                 // Physical address of RX buffer
static uint8_t *rx_buffer;                      // Virtual address

static uint32_t tx_buffer_phys[TX_BUF_COUNT];   // Physical address per TX buffer
static uint8_t *tx_buffer[TX_BUF_COUNT];        // Virtual address per TX buffer

// Track which TX descriptor is next
static int tx_current = 0;

// Track where we are in the RX ring buffer
static uint16_t rx_read_ptr = 0;

// MAC Address storage
static uint8_t mac_address[6];

// RX Packet header that the NIC prepends to each packet
typedef struct rx_header
{
    uint16_t status;
    uint16_t length;    // Includes 4 byte CRC
} __attribute__((packed)) rx_header_t;


// Allocate DMA Buffers
static int alloc_dma_buffers(void)
{
    // Allocate RX Buffer - contiguous pages needed
    rx_buffer_phys = kernel->alloc_phys_pages(RX_BUF_PAGES);

    if (rx_buffer_phys == 0)
    {
        kernel->printf("[DRIVER] RTL8139 - Failed to allocate %d contiguous RX pages!\n", RX_BUF_PAGES);

        return -1;
    }

    // Map the contiguous physical pages to virtual address
    rx_buffer = (uint8_t *)kernel->map_physical(rx_buffer_phys, RX_BUF_PAGES * 4096, 0);

    if (!rx_buffer)
    {
        kernel->printf("[DRIVER] RTL8139 - Failed to map RX buffer!\n");
        kernel->free_phys_pages(rx_buffer_phys, RX_BUF_PAGES);

        return -1;
    }

    // Allocate TX Buffers (1 Page for each should be fine)
    int i;
    for (i = 0; i < TX_BUF_COUNT; i++)
    {
        tx_buffer_phys[i] = kernel->alloc_phys_page();

        if (tx_buffer_phys[i] == 0)
        {
            kernel->printf("[DRIVER] RTL8139 - Failed to allocate TX buffer %d!\n", i);

            goto fail_tx;
        }

        tx_buffer[i] = (uint8_t *)kernel->map_physical(tx_buffer_phys[i], 4096, 0);

        if (!tx_buffer[i])
        {
            kernel->printf("[DRIVER] RTL8139 - Failed to map TX buffer %d!\n", i);
            kernel->free_phys_page(tx_buffer_phys[i]);

            goto fail_tx;
        }
    }

    kernel->printf("[DRIVER] RTL8139 - DMA Buffers Allocated!\n");

    return 0;

fail_tx:
    // Cleanup buffers
    for (int j = 0; j < i; j++)
    {
        kernel->free_phys_page(tx_buffer_phys[j]);
        tx_buffer[j] = NULL;
    }

    kernel->free_phys_pages(rx_buffer_phys, RX_BUF_PAGES);
    rx_buffer = NULL;

    return -1;
}

// Free DMA Buffers
static void free_dma_buffers(void)
{
    // Free TX buffers
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        if (tx_buffer_phys[i])
        {
            kernel->free_phys_page(tx_buffer_phys[i]);
            tx_buffer_phys[i] = 0;
            tx_buffer[i] = NULL;
        }
    }

    // Free RX buffer
    if (rx_buffer_phys)
    {
        kernel->free_phys_pages(rx_buffer_phys, RX_BUF_PAGES);
        rx_buffer_phys = 0;
        rx_buffer = NULL;
    }

    kernel->printf("[DRIVER] RTL8139 - DMA Buffers freed!\n");
}

// Read MAC address from the NIC
static void read_mac_address(void)
{
    uint32_t mac0 = kernel->inl(io_base + REG_MAC0);
    uint16_t mac4 = kernel->inw(io_base + REG_MAC4);

    mac_address[0] = (mac0 >> 0) & 0xFF;
    mac_address[1] = (mac0 >> 8) & 0xFF;
    mac_address[2] = (mac0 >> 16) & 0xFF;
    mac_address[3] = (mac0 >> 24) & 0xFF;
    mac_address[4] = (mac4 >> 0) & 0xFF;
    mac_address[5] = (mac4 >> 8) & 0xFF;

    kernel->printf("[DRIVER] RTL8139 - MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   mac_address[0], mac_address[1], mac_address[2],
                   mac_address[3], mac_address[4], mac_address[5]);
}

// Init RX
static void init_rx(void)
{
    // Zero the RX buffer
    for (int i = 0; i < RX_BUF_SIZE; i++)
    {
        rx_buffer[i] = 0;
    }

    // Tell NIC where our RX buffer is located
    kernel->outl(io_base + REG_RXBUF, rx_buffer_phys);

    // Configure receiver - accept our MAC, broadcast, and multicast
    uint32_t rcr = RCR_APM | RCR_AB | RCR_AM | RCR_RBLEN_8K;
    kernel->outl(io_base + REG_RCR, rcr);

    // Reset read pointer - hardware quirk requires starting at 0xFFF0
    rx_read_ptr = 0;
    kernel->outw(io_base + REG_CAPR, 0xFFF0);

    kernel->printf("[DRIVER] RTL8139 - RX Ready!\n");
}

// Init TX
static void init_tx(void)
{
    // Zero the TX buffers and set their addresses
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        for (int j = 0; j < TX_BUF_SIZE; j++)
        {
            tx_buffer[i][j] = 0;
        }

        // Tell NIC each TX buffers physical address
        kernel->outl(io_base + REG_TXADDR0 + (i * 4), tx_buffer_phys[i]);
    }

    // Configure transmitter - normal inter-frame gap, 2048 byte DMA burst
    uint32_t tcr = TCR_IFG_NORMAL | TCR_MXDMA_2048;
    kernel->outl(io_base + REG_TCR, tcr);

    tx_current = 0;

    kernel->printf("[DRIVER] RTL8139 - TX Ready!\n");
}

// Enable the NIC (RX and TX)
static void device_enable(void)
{
    kernel->outb(io_base + REG_CMD, CMD_RX_ENABLE | CMD_TX_ENABLE);

    kernel->printf("[DRIVER] RTL8139 - RX/TX Enabled!\n");
}

// Enable interrupts on the NIC
static void enable_interrupts(void)
{
    // Enable the interrupts we care about
    uint16_t imr = INT_RX_OK | INT_TX_OK | INT_RX_ERR | INT_TX_ERR | INT_RX_OVERFLOW;
    kernel->outw(io_base + REG_IMR, imr);

    // Unmask IRQ at the PIC
    kernel->pic_clear_mask(device_irq);

    kernel->printf("[DRIVER] RTL8139 - Interrupts Enabled, IRQ=%d\n", device_irq);
}

// Handle received packets
static void handle_rx(void)
{
    // Process all available packets
    while (!(kernel->inb(io_base + REG_CMD) & CMD_BUF_EMPTY))
    {
        // Get packet header from current position
        rx_header_t *header = (rx_header_t *)(rx_buffer + rx_read_ptr);

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
        uint8_t *packet_data = rx_buffer + rx_read_ptr + 4;
        uint16_t packet_len = length - 4;   // Exclude CRC

        // TODO: Pass packet to network stack
        // For now just print some info
        kernel->printf("[DRIVER] RTL8139 - RX packet: len=%d, src=%02x:%02x:%02x:%02x:%02x:%02x\n",
                       packet_len,
                       packet_data[6], packet_data[7], packet_data[8],
                       packet_data[9], packet_data[10], packet_data[11]);

        // Advance read pointer - must be 4 byte aligned
        rx_read_ptr = (rx_read_ptr + 4 + length + 3) & ~3;
        rx_read_ptr %= 8192;    // Wrap at 8K buffer size

        // Update CAPR - hardware quirk requires subtracting 16
        kernel->outw(io_base + REG_CAPR, rx_read_ptr - 16);
    }
}

// Handle TX completion
static void handle_tx(void)
{
    // Check all 4 TX descriptors for completion
    for (int i = 0; i < TX_BUF_COUNT; i++)
    {
        uint32_t status = kernel->inl(io_base + REG_TXSTATUS0 + (i * 4));

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
int rtl8139_send(const uint8_t *data, uint16_t length)
{
    if (!data || length == 0 || length > TX_BUF_SIZE)
    {
        return -1;
    }

    // Wait for current descriptor to be free
    uint32_t status = kernel->inl(io_base + REG_TXSTATUS0 + (tx_current * 4));

    if (status & TX_STATUS_OWN)
    {
        // NIC still owns this buffer
        kernel->printf("[DRIVER] RTL8139 - TX buffer %d busy\n", tx_current);

        return -1;
    }

    // Copy packet data to TX buffer
    for (uint16_t i = 0; i < length; i++)
    {
        tx_buffer[tx_current][i] = data[i];
    }

    // Tell the NIC to send - write length to status register
    // Bit 13 (OWN) must be 0, bits 0-12 are the size
    kernel->outl(io_base + REG_TXSTATUS0 + (tx_current * 4), length);

    // Move to next descriptor
    tx_current = (tx_current + 1) % TX_BUF_COUNT;

    return 0;
}

// PCI scan callback
static void pci_scan_callback(const pci_device_t *dev, void *ctx)
{
    (void)ctx;

    if (dev->vendor_id == VENDOR_ID && dev->device_id == DEVICE_ID)
    {
        device = *dev;
        device_found = 1;

        kernel->printf("[DRIVER] RTL8139 Network Card found at PCI %d:%d.%d\n", dev->bus, dev->device, dev->function);
    }
}

// Reset Device
// - Write CMD_RESET to command register
// - Poll until the chip clears the bit
// - All registers return to default values
static void device_reset(void)
{
    // Send reset command
    kernel->outb(io_base + REG_CMD, CMD_RESET);

    // Wait for reset to complete, bit should clear itself
    int timeout = 1000;

    while ((kernel->inb(io_base + REG_CMD) & CMD_RESET) && timeout > 0)
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

void ddf_driver_init(kernel_exports_t *exports)
{
    kernel = exports;

    // Scan for RTL8139 Network Card
    kernel->pci_enum_devices(pci_scan_callback, NULL);

    if (!device_found)
    {
        kernel->printf("[DRIVER] Could not find a RTL8139 device!\n");

        return;
    }

    // Enable device
    kernel->pci_enable_device(&device);

    uint32_t bar_size;
    int is_mmio;

    // Get I/O base from BAR0
    if (kernel->pci_get_bar(&device, 0, &io_base, &bar_size, &is_mmio) < 0)
    {
        kernel->printf("[DRIVER] Could not find BAR0 for RTL8139 device!\n");

        return;
    }

    // Read IRQ from PCI config
    uint32_t irq_reg = kernel->pci_config_read32(device.bus, device.device, device.function, PCI_INTERRUPT_LINE);
    device_irq = (uint8_t)(irq_reg & 0xFF);

    kernel->printf("[DRIVER] RTL8139 - I/O base=0x%x, IRQ=%d\n", io_base, device_irq);

    // Allocate DMA buffers
    if (alloc_dma_buffers() < 0)
    {
        return;
    }

    // Reset the chip
    device_reset();

    // Read MAC address
    read_mac_address();

    // Initialize RX and TX
    init_rx();
    init_tx();

    // Enable RX/TX
    device_enable();

    // Enable interrupts
    enable_interrupts();

    kernel->printf("[DRIVER] RTL8139 Network Driver Installed!\n");
}

void ddf_driver_exit(void)
{
    // Disable interrupts
    kernel->outw(io_base + REG_IMR, 0);
    kernel->pic_set_mask(device_irq);

    // Disable RX/TX
    kernel->outb(io_base + REG_CMD, 0);

    // Free DMA buffers
    free_dma_buffers();

    kernel->printf("[DRIVER] RTL8139 Network Driver Uninstalled!\n");
}

void ddf_driver_irq(unsigned irq, void *context)
{
    (void)irq;
    (void)context;

    // Read interrupt status
    uint16_t status = kernel->inw(io_base + REG_ISR);

    if (status == 0)
    {
        return;     // Not our interrupt
    }

    // Handle RX
    if (status & INT_RX_OK)
    {
        handle_rx();
    }

    // Handle TX
    if (status & INT_TX_OK)
    {
        handle_tx();
    }

    // Handle errors
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

        // Reset RX by toggling the enable bit
        kernel->outb(io_base + REG_CMD, CMD_TX_ENABLE);
        kernel->outb(io_base + REG_CMD, CMD_TX_ENABLE | CMD_RX_ENABLE);
    }

    // Acknowledge all interrupts by writing status back
    kernel->outw(io_base + REG_ISR, status);
}
