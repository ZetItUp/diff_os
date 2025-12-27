#include <stdio.h>
#include <console.h>

int main()
{
    console_set_fgcolor(CONSOLE_COLOR_LIGHT_GREEN);
    printf("Hello World!\n");
    console_set_fgcolor(CONSOLE_COLOR_DEFAULT);

    return 0;
}
