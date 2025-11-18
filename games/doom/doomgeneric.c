#include <stdio.h>

#include "m_argv.h"

#include "doomgeneric.h"

pixel_t* DG_ScreenBuffer = NULL;

void M_FindResponseFile(void);
void D_DoomMain (void);


void doomgeneric_Create(int argc, char **argv)
{
    printf("[DG] doomgeneric_Create argc=%d\n", argc);
    for (int i = 0; i < argc; ++i)
    {
        printf("[DG] argv[%d]='%s'\n", i, argv[i] ? argv[i] : "(null)");
    }

    // save arguments
    myargc = argc;
    myargv = argv;

    printf("[DG] Running M_FindResponseFile\n");
    M_FindResponseFile();

    printf("[DG] Allocating screen buffer (%dx%d)\n", DOOMGENERIC_RESX, DOOMGENERIC_RESY);
    DG_ScreenBuffer = malloc(DOOMGENERIC_RESX * DOOMGENERIC_RESY * 4);

    printf("[DG] Calling DG_Init\n");
    DG_Init();
    printf("[DG] DG_Init returned\n");

    printf("[DG] Entering D_DoomMain\n");
    D_DoomMain ();
    printf("[DG] D_DoomMain returned (should not happen)\n");
}
