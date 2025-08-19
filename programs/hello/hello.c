#include <stdio.h>
#include <console.h>

int main()
{
    uint8_t fg_color = 0;
    console_get_fgcolor(&fg_color);
    console_set_fgcolor(CONSOLE_COLOR_LIGHT_GREEN);
    printf("Hello World!\n");
    console_set_fgcolor(fg_color);

    return 0;
}
