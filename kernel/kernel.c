#include "string.h"
#include "paging.h"

void kmain()
{
    init_paging();

    char* video = (char*)0xB8000;
    video[0] = 'H';
    video[1] = 0x3F; // vit text, svart bakgrund
    video[2] = 'i';
    video[3] = 0x0F;

    while(1);
}
