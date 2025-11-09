//
// Copyright(C) 1993-1996 Id Software, Inc.
// Copyright(C) 2005-2014 Simon Howard
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// DESCRIPTION:
//	Handles WAD file header, directory, lump I/O.
//




#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "doomtype.h"

#include "config.h"
#include "d_iwad.h"
#include "i_swap.h"
#include "i_system.h"
#include "i_video.h"
#include "m_misc.h"
#include "z_zone.h"

#include "w_wad.h"

typedef struct
{
    // Should be "IWAD" or "PWAD".
    char		identification[4];		
    int			numlumps;
    int			infotableofs;
} PACKEDATTR wadinfo_t;


typedef struct
{
    int			filepos;
    int			size;
    char		name[8];
} PACKEDATTR filelump_t;

//
// GLOBALS
//

// Location of each lump on disk.

lumpinfo_t *lumpinfo;		
unsigned int numlumps = 0;

// Hash table for fast lookups

static lumpinfo_t **lumphash;

static const char lumpname_impxa1[] = "IMPXA1";
static const char lumpname_ettna1[] = "ETTNA1";
static const char lumpname_possa1[] = "POSSA1";
static const char lumpname_agrda1[] = "AGRDA1";

static const char *trace_lumpnames[] = {
    lumpname_impxa1,
    lumpname_ettna1,
    lumpname_possa1,
    lumpname_agrda1,
};

static void W_CopyLumpName(const char src[8], char dst[9])
{
    memcpy(dst, src, 8);
    dst[8] = '\0';
    for (int i = 7; i >= 0; --i)
    {
        if (dst[i] == ' ' || dst[i] == '\0')
        {
            dst[i] = '\0';
        }
        else
        {
            break;
        }
    }
}

static void W_CopyCStringName(const char *src, char dst[9])
{
    if (src == NULL)
    {
        dst[0] = '\0';
        return;
    }

    int i = 0;

    // Copy up to 8 characters or until we hit '\0'
    for (; i < 8 && src[i] != '\0'; ++i)
    {
        dst[i] = src[i];
    }

    // Pad remaining bytes with NUL
    for (; i < 8; ++i)
    {
        dst[i] = '\0';
    }

    dst[8] = '\0';

    // Trim trailing spaces to match WAD comparisons
    for (i = 7; i >= 0; --i)
    {
        if (dst[i] == ' ' || dst[i] == '\0')
        {
            dst[i] = '\0';
        }
        else
        {
            break;
        }
    }
}

static int W_LumpNameEqual(const char lump[8], const char *name)
{
    for (int i = 0; i < 8; ++i)
    {
        unsigned char c1 = (unsigned char)lump[i];
        unsigned char c2 = (unsigned char)name[i];

        if (c1 >= 'a' && c1 <= 'z')
        {
            c1 = (unsigned char)(c1 - 'a' + 'A');
        }
        if (c2 >= 'a' && c2 <= 'z')
        {
            c2 = (unsigned char)(c2 - 'a' + 'A');
        }

        if (c2 == '\0')
        {
            return c1 == '\0';
        }

        if (c1 != c2)
        {
            return 0;
        }

        if (c1 == '\0')
        {
            return 1;
        }
    }

    return name[8] == '\0';
}

static int W_LumpNameMatches(const char lump[8], const char *name)
{
    int cmp = strncasecmp(lump, name, 8);

    if (cmp != 0)
    {
        return 0;
    }

    char lhs[9], rhs[9];
    W_CopyLumpName(lump, lhs);
    W_CopyCStringName(name, rhs);

    if (!W_LumpNameEqual(lump, name))
    {
        printf("[IWADDBG] strncasecmp bug! matched '%s' vs '%s' but W_LumpNameEqual disagrees\n",
               lhs, rhs);
        return 0;
    }

    return 1;
}

// Hash function used for lump names.

unsigned int W_LumpNameHash(const char *s)
{
    // This is the djb2 string hash function, modded to work on strings
    // that have a maximum length of 8.

    unsigned int result = 5381;
    unsigned int i;

    for (i=0; i < 8 && s[i] != '\0'; ++i)
    {
        result = ((result << 5) ^ result ) ^ toupper((int)s[i]);
    }

    return result;
}

// Increase the size of the lumpinfo[] array to the specified size.
static void ExtendLumpInfo(int newnumlumps)
{
    lumpinfo_t *newlumpinfo;
    unsigned int i;

    newlumpinfo = calloc(newnumlumps, sizeof(lumpinfo_t));

    if (newlumpinfo == NULL)
    {
	I_Error ("Couldn't realloc lumpinfo");
    }

    // Copy over lumpinfo_t structures from the old array. If any of
    // these lumps have been cached, we need to update the user
    // pointers to the new location.
    for (i = 0; i < numlumps && i < newnumlumps; ++i)
    {
        memcpy(&newlumpinfo[i], &lumpinfo[i], sizeof(lumpinfo_t));

        if (newlumpinfo[i].cache != NULL)
        {
            Z_ChangeUser(newlumpinfo[i].cache, &newlumpinfo[i].cache);
        }

        // We shouldn't be generating a hash table until after all WADs have
        // been loaded, but just in case...
        if (lumpinfo[i].next != NULL)
        {
            int nextlumpnum = lumpinfo[i].next - lumpinfo;
            newlumpinfo[i].next = &newlumpinfo[nextlumpnum];
        }
    }

    // All done.
    free(lumpinfo);
    lumpinfo = newlumpinfo;
    numlumps = newnumlumps;
}

//
// LUMP BASED ROUTINES.
//

//
// W_AddFile
// All files are optional, but at least one file must be
//  found (PWAD, if all required lumps are present).
// Files with a .wad extension are wadlink files
//  with multiple lumps.
// Other files are single lumps with the base filename
//  for the lump name.

wad_file_t *W_AddFile (char *filename)
{
    wadinfo_t header;
    lumpinfo_t *lump_p;
    unsigned int i;
    wad_file_t *wad_file;
    int length;
    int startlump;
    filelump_t *fileinfo;
    filelump_t *filerover;
    int newnumlumps;

    // open the file and add to directory

    wad_file = W_OpenFile(filename);

    if (wad_file == NULL)
    {
		printf (" couldn't open %s\n", filename);
		return NULL;
    }

    newnumlumps = numlumps;

    if (strcasecmp(filename+strlen(filename)-3 , "wad" ) )
    {
    	// single lump file

        // fraggle: Swap the filepos and size here.  The WAD directory
        // parsing code expects a little-endian directory, so will swap
        // them back.  Effectively we're constructing a "fake WAD directory"
        // here, as it would appear on disk.

		fileinfo = Z_Malloc(sizeof(filelump_t), PU_STATIC, 0);
		fileinfo->filepos = LONG(0);
		fileinfo->size = LONG(wad_file->length);

        // Name the lump after the base of the filename (without the
        // extension).

		M_ExtractFileBase (filename, fileinfo->name);
		newnumlumps++;
    }
    else 
    {
    	// WAD file
        W_Read(wad_file, 0, &header, sizeof(header));

		if (strncmp(header.identification,"IWAD",4))
		{
			// Homebrew levels?
			if (strncmp(header.identification,"PWAD",4))
			{
			I_Error ("Wad file %s doesn't have IWAD "
				 "or PWAD id\n", filename);
			}

			// ???modifiedgame = true;
		}

		header.numlumps = LONG(header.numlumps);
		header.infotableofs = LONG(header.infotableofs);
		length = header.numlumps*sizeof(filelump_t);
		fileinfo = Z_Malloc(length, PU_STATIC, 0);

        W_Read(wad_file, header.infotableofs, fileinfo, length);
        newnumlumps += header.numlumps;
    }

    // Increase size of numlumps array to accomodate the new file.
    startlump = numlumps;
    ExtendLumpInfo(newnumlumps);

    lump_p = &lumpinfo[startlump];

    filerover = fileinfo;

    for (i=startlump; i<numlumps; ++i)
    {
		lump_p->wad_file = wad_file;
		lump_p->position = LONG(filerover->filepos);
		lump_p->size = LONG(filerover->size);
			lump_p->cache = NULL;
		strncpy(lump_p->name, filerover->name, 8);

			++lump_p;
			++filerover;
    }

    Z_Free(fileinfo);

    if (lumphash != NULL)
    {
        Z_Free(lumphash);
        lumphash = NULL;
    }

    return wad_file;
}



//
// W_NumLumps
//
int W_NumLumps (void)
{
    return numlumps;
}



// TEMP: Dummy function to work around linking issue
static void DummyPrintFunc(void)
{
    printf("DUMMY\n");
}

//
// W_CheckNumForName
// Returns -1 if name not found.
//

int W_CheckNumForName (char* name)
{
    putchar('X');
    lumpinfo_t *lump_p;
    int i;
    char normalized[9];

    // Debug: use putchar only to avoid printf issues
    putchar('[');
    putchar('W');
    putchar(']');
    W_CopyCStringName(name, normalized);
    putchar('Y');
    printf("[WCHECK] W_CheckNumForName called: name=%p normalized='%s'\n", (void*)name, normalized);
    putchar('Z');

    // Debug IMPXA1 lookups specifically - ALWAYS print this
    int is_impx_lookup = (strcasecmp(normalized, "IMPXA1") == 0);
    if (is_impx_lookup)
    {
        printf("[DEBUG-IMPX] W_CheckNumForName called for IMPXA1, lumphash=%p\n", (void *)lumphash);
    }

    // TEMP: Log first 8 bytes of name pointer to see what we're actually getting
    static int call_count = 0;
    call_count++;
    if (call_count > 500 && call_count < 520)
    {
        printf("[IWADDBG] W_CheckNumForName #%d: input ptr=%p normalized='%s'\n",
               call_count, (void *)name, normalized);
        printf("  raw bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
               (unsigned char)name[0], (unsigned char)name[1], (unsigned char)name[2], (unsigned char)name[3],
               (unsigned char)name[4], (unsigned char)name[5], (unsigned char)name[6], (unsigned char)name[7]);
    }

    // TEMP DEBUG: unconditionally trace lookups that match these names
    int is_imp = (strcasecmp(normalized, "IMPXA1") == 0);
    int is_ett = (strcasecmp(normalized, "ETTNA1") == 0);
    int is_poss = (strcasecmp(normalized, "POSSA1") == 0);
    int is_agr = (strcasecmp(normalized, "AGRDA1") == 0);

    int trace_by_ptr = 0;

    for (int idx = 0; idx < (int)(sizeof(trace_lumpnames) / sizeof(trace_lumpnames[0])); ++idx)
    {
        if (name == trace_lumpnames[idx])
        {
            printf("[IWADDBG] W_CheckNumForName pointer match idx=%d normalized=%s ptr=%p\n",
                   idx, normalized, (void *)name);
            trace_by_ptr = 1;
            break;
        }
    }

    int trace_unique = is_imp || is_ett || is_poss || is_agr || trace_by_ptr;

    // Do we have a hash table yet?

    if (lumphash != NULL)
    {
        int hash;

        // We do! Excellent.

        hash = W_LumpNameHash(name) % numlumps;

        // ALWAYS trace IMPXA1 lookups
        if (trace_unique || is_impx_lookup)
        {
            printf("[IWADDBG] W_CheckNumForName ENTER target=%s hash=%d numlumps=%u\n",
                   normalized, hash, numlumps);
        }

        for (lump_p = lumphash[hash]; lump_p != NULL; lump_p = lump_p->next)
        {
            if (trace_unique || is_impx_lookup)
            {
                char cand[9];
                W_CopyLumpName(lump_p->name, cand);
                printf("[IWADDBG]   candidate '%s' index=%d\n", cand, (int)(lump_p - lumpinfo));
            }

            if (W_LumpNameMatches(lump_p->name, name))
            {
                int result_idx = lump_p - lumpinfo;
                if (trace_unique || is_impx_lookup)
                {
                    char matched[9];
                    W_CopyLumpName(lump_p->name, matched);
                    printf("[IWADDBG]   MATCHED '%s' at index=%d\n", matched, result_idx);
                }
                return result_idx;
            }
        }

        if (trace_unique)
        {
            printf("[IWADDBG]   not found in hash table\n");
        }
    } 
    else
    {
        // We don't have a hash table generate yet. Linear search :-(
        // 
        // scan backwards so patch lump files take precedence

        for (i=numlumps-1; i >= 0; --i)
        {
            if (trace_unique)
            {
                char cand[9];
                W_CopyLumpName(lumpinfo[i].name, cand);
                printf("[IWADDBG] linear candidate idx=%d '%s'\n", i, cand);
            }

            if (W_LumpNameMatches(lumpinfo[i].name, name))
            {
                return i;
            }
        }
    }

    // TFB. Not found.

    printf("[IWADDBG-EXIT] W_CheckNumForName returning -1 (not found) for '%s'\n",
           name ? name : "(null)");
    return -1;
}




//
// W_GetNumForName
// Calls W_CheckNumForName, but bombs out if not found.
//
int W_GetNumForName (char* name)
{
    int	i;

    i = W_CheckNumForName (name);

    if (i < 0)
    {
        I_Error ("W_GetNumForName: %s not found!", name);
    }
 
    return i;
}


//
// W_LumpLength
// Returns the buffer size needed to load the given lump.
//
int W_LumpLength (unsigned int lump)
{
    if (lump >= numlumps)
    {
	I_Error ("W_LumpLength: %i >= numlumps", lump);
    }

    return lumpinfo[lump].size;
}



//
// W_ReadLump
// Loads the lump into the given buffer,
//  which must be >= W_LumpLength().
//
void W_ReadLump(unsigned int lump, void *dest)
{
    int c;
    lumpinfo_t *l;
	
    if (lump >= numlumps)
    {
	I_Error ("W_ReadLump: %i >= numlumps", lump);
    }

    l = lumpinfo+lump;
	
    I_BeginRead ();
	
    c = W_Read(l->wad_file, l->position, dest, l->size);

    if (c < l->size)
    {
	I_Error ("W_ReadLump: only read %i of %i on lump %i",
		 c, l->size, lump);	
    }

    I_EndRead ();
}




//
// W_CacheLumpNum
//
// Load a lump into memory and return a pointer to a buffer containing
// the lump data.
//
// 'tag' is the type of zone memory buffer to allocate for the lump
// (usually PU_STATIC or PU_CACHE).  If the lump is loaded as 
// PU_STATIC, it should be released back using W_ReleaseLumpNum
// when no longer needed (do not use Z_ChangeTag).
//

void *W_CacheLumpNum(int lumpnum, int tag)
{
    byte *result;
    lumpinfo_t *lump;

    if ((unsigned)lumpnum >= numlumps)
    {
	I_Error ("W_CacheLumpNum: %i >= numlumps", lumpnum);
    }

    lump = &lumpinfo[lumpnum];

    // Get the pointer to return.  If the lump is in a memory-mapped
    // file, we can just return a pointer to within the memory-mapped
    // region.  If the lump is in an ordinary file, we may already
    // have it cached; otherwise, load it into memory.

    if (lump->wad_file->mapped != NULL)
    {
        // Memory mapped file, return from the mmapped region.

        result = lump->wad_file->mapped + lump->position;
    }
    else if (lump->cache != NULL)
    {
        // Already cached, so just switch the zone tag.

        result = lump->cache;
        Z_ChangeTag(lump->cache, tag);
    }
    else
    {
        // Not yet loaded, so load it now

        lump->cache = Z_Malloc(W_LumpLength(lumpnum), tag, &lump->cache);
	W_ReadLump (lumpnum, lump->cache);
        result = lump->cache;
    }
	
    return result;
}



//
// W_CacheLumpName
//
void *W_CacheLumpName(char *name, int tag)
{
    return W_CacheLumpNum(W_GetNumForName(name), tag);
}

// 
// Release a lump back to the cache, so that it can be reused later 
// without having to read from disk again, or alternatively, discarded
// if we run out of memory.
//
// Back in Vanilla Doom, this was just done using Z_ChangeTag 
// directly, but now that we have WAD mmap, things are a bit more
// complicated ...
//

void W_ReleaseLumpNum(int lumpnum)
{
    lumpinfo_t *lump;

    if ((unsigned)lumpnum >= numlumps)
    {
	I_Error ("W_ReleaseLumpNum: %i >= numlumps", lumpnum);
    }

    lump = &lumpinfo[lumpnum];

    if (lump->wad_file->mapped != NULL)
    {
        // Memory-mapped file, so nothing needs to be done here.
    }
    else
    {
        Z_ChangeTag(lump->cache, PU_CACHE);
    }
}

void W_ReleaseLumpName(char *name)
{
    W_ReleaseLumpNum(W_GetNumForName(name));
}

#if 0

//
// W_Profile
//
int		info[2500][10];
int		profilecount;

void W_Profile (void)
{
    int		i;
    memblock_t*	block;
    void*	ptr;
    char	ch;
    FILE*	f;
    int		j;
    char	name[9];
	
	
    for (i=0 ; i<numlumps ; i++)
    {	
	ptr = lumpinfo[i].cache;
	if (!ptr)
	{
	    ch = ' ';
	    continue;
	}
	else
	{
	    block = (memblock_t *) ( (byte *)ptr - sizeof(memblock_t));
	    if (block->tag < PU_PURGELEVEL)
		ch = 'S';
	    else
		ch = 'P';
	}
	info[i][profilecount] = ch;
    }
    profilecount++;
#if ORIGCODE
    f = fopen ("waddump.txt","w");
    name[8] = 0;

    for (i=0 ; i<numlumps ; i++)
    {
	memcpy (name,lumpinfo[i].name,8);

	for (j=0 ; j<8 ; j++)
	    if (!name[j])
		break;

	for ( ; j<8 ; j++)
	    name[j] = ' ';

	fprintf (f,"%s ",name);

	for (j=0 ; j<profilecount ; j++)
	    fprintf (f,"    %c",info[i][j]);

	fprintf (f,"\n");
    }
    fclose (f);
#endif
}


#endif

// Generate a hash table for fast lookups

void W_GenerateHashTable(void)
{
    unsigned int i;

    // Free the old hash table, if there is one

    if (lumphash != NULL)
    {
        Z_Free(lumphash);
    }

    // Generate hash table
    if (numlumps > 0)
    {
        lumphash = Z_Malloc(sizeof(lumpinfo_t *) * numlumps, PU_STATIC, NULL);
        memset(lumphash, 0, sizeof(lumpinfo_t *) * numlumps);

        for (i=0; i<numlumps; ++i)
        {
            unsigned int hash;

            hash = W_LumpNameHash(lumpinfo[i].name) % numlumps;

            // Hook into the hash table

            lumpinfo[i].next = lumphash[hash];
            lumphash[hash] = &lumpinfo[i];
        }
    }

    // All done!
}

// Lump names that are unique to particular game types. This lets us check
// the user is not trying to play with the wrong executable, eg.
// chocolate-doom -iwad hexen.wad.
static const struct
{
    GameMission_t mission;
    char *lumpname;
} unique_lumps[] = {
    { doom,    (char *)lumpname_possa1 },
    { heretic, (char *)lumpname_impxa1 },
    { hexen,   (char *)lumpname_ettna1 },
    { strife,  (char *)lumpname_agrda1 },
};

void W_CheckCorrectIWAD(GameMission_t mission)
{
    printf("[WCORR] W_CheckCorrectIWAD ENTER mission=%d\n", (int)mission);
    int i;
    int lumpnum;
    static int printed_trace_ptrs = 0;

    if (!printed_trace_ptrs)
    {
        printed_trace_ptrs = 1;
        printf("[IWADDBG] trace_lump ptrs: IMPXA1=%p ETTNA1=%p POSSA1=%p AGRDA1=%p\n",
               (void *)lumpname_impxa1,
               (void *)lumpname_ettna1,
               (void *)lumpname_possa1,
               (void *)lumpname_agrda1);
    }

    for (i = 0; i < arrlen(unique_lumps); ++i)
    {
        if (mission != unique_lumps[i].mission)
        {
            char expected[9];
            W_CopyCStringName(unique_lumps[i].lumpname, expected);
            printf("[IWADDBG-v2] mission=%d checking unique lump '%s' ptr=%p\n",
                   (int)mission, expected, (void *)unique_lumps[i].lumpname);

            lumpnum = W_CheckNumForName(unique_lumps[i].lumpname);

            if (lumpnum >= 0)
            {
                char actual[9];
                W_CopyLumpName(lumpinfo[lumpnum].name, actual);

                printf("[IWADDBG] lookup '%s' returned index=%d actual='%s'\n",
                       expected, lumpnum, actual);

                printf("  ERROR: Found '%s' but actual lump name is '%s' at index %d\n",
                       unique_lumps[i].lumpname, actual, lumpnum);
                I_Error("\nYou are trying to use a %s IWAD file with "
                        "the %s%s binary.\nThis isn't going to work.\n"
                        "You probably want to use the %s%s binary.",
                        D_SuggestGameName(unique_lumps[i].mission,
                                          indetermined),
                        PROGRAM_PREFIX,
                        D_GameMissionString(mission),
                        PROGRAM_PREFIX,
                        D_GameMissionString(unique_lumps[i].mission));
            }
            else
            {
                printf("[IWADDBG] unique lump '%s' not found (mission=%d)\n",
                       expected, (int)mission);
            }
        }
    }

    printf("[IWADDBG] W_CheckCorrectIWAD done for mission=%d\n", (int)mission);
}
