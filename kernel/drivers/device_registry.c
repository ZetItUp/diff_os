#include "drivers/device.h"

void device_registry_init(void)
{
    device_class_register(DEVICE_CLASS_UNKNOWN, "Unknown");
    device_class_register(DEVICE_CLASS_INPUT, "Input");
    device_class_register(DEVICE_CLASS_NETWORK, "Network");
    device_class_register(DEVICE_CLASS_DISPLAY, "Display");
    device_class_register(DEVICE_CLASS_TTY, "TTY");
    device_class_register(DEVICE_CLASS_STORAGE, "Storage");
    device_class_register(DEVICE_CLASS_SERIAL, "Serial");
    device_class_register(DEVICE_CLASS_TIMER, "Timer");

    device_bus_register(BUS_TYPE_UNKNOWN, "Unknown");
    device_bus_register(BUS_TYPE_ISA, "ISA");
    device_bus_register(BUS_TYPE_PCI, "PCI");
    device_bus_register(BUS_TYPE_USB, "USB");
    device_bus_register(BUS_TYPE_PS2, "PS/2");
    device_bus_register(BUS_TYPE_VIRTUAL, "Virtual");
}
