#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define MAX_NAME_LEN    64
#define MAX_PATH_LEN    256

typedef struct
{
    char name[MAX_NAME_LEN];
    char path[MAX_PATH_LEN];
    uint8_t used;
} cmd_slot_t;

int cmdreg_init(const char *map_path);
const char *cmdreg_lookup(const char *name);
bool cmdreg_add(const char *name, const char *path);
void cmdreg_reset(void);
