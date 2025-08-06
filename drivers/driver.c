#include "stdarg.h"
#include "drivers/driver.h"

void driver_printf(kernel_exports_t *exports, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    exports->vprintf(fmt, ap);
    va_end(ap);
}

