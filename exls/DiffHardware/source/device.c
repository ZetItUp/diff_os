#include <device.h>
#include <syscall.h>

// Syscall numbers for device operations
#define SYSTEM_DEVICE_COUNT 78
#define SYSTEM_DEVICE_INFO  79

int device_count(int class_filter)
{
    return do_sys(SYSTEM_DEVICE_COUNT, class_filter, 0, 0, 0);
}

int device_get_info(int index, device_info_t *info)
{
    if (!info)
    {
        return -1;
    }

    return do_sys(SYSTEM_DEVICE_INFO, index, (int)(uintptr_t)info, 0, 0);
}

const char *device_class_name(device_class_t class)
{
    switch (class)
    {
        case DEVICE_CLASS_UNKNOWN:
            return "Unknown";
        case DEVICE_CLASS_INPUT:
            return "Input";
        case DEVICE_CLASS_DISPLAY:
            return "Display";
        case DEVICE_CLASS_NETWORK:
            return "Network";
        case DEVICE_CLASS_TTY:
            return "TTY";
        case DEVICE_CLASS_STORAGE:
            return "Storage";
        case DEVICE_CLASS_SERIAL:
            return "Serial";
        case DEVICE_CLASS_TIMER:
            return "Timer";
        default:
            return "Invalid";
    }
}

const char *device_bus_name(uint8_t bus_type)
{
    switch (bus_type)
    {
        case BUS_TYPE_UNKNOWN:
            return "Unknown";
        case BUS_TYPE_ISA:
            return "ISA";
        case BUS_TYPE_PCI:
            return "PCI";
        case BUS_TYPE_USB:
            return "USB";
        case BUS_TYPE_PS2:
            return "PS/2";
        case BUS_TYPE_VIRTUAL:
            return "Virtual";
        default:
            return "Invalid";
    }
}

const char *device_status_name(device_status_t status)
{
    switch (status)
    {
        case DEVICE_STATUS_OK:
            return "OK";
        case DEVICE_STATUS_ERROR:
            return "Error";
        case DEVICE_STATUS_DISABLED:
            return "Disabled";
        case DEVICE_STATUS_BUSY:
            return "Busy";
        default:
            return "Invalid";
    }
}
