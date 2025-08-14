#pragma once

#include <stdint.h>

#ifndef NAME_MAX
#define NAME_MAX    128
#endif

#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#endif
#ifndef DT_REG
#define DT_REG     8
#endif
#ifndef DT_DIR
#define DT_DIR     4
#endif

typedef struct dirent {
    uint32_t d_id;            
    char     d_name[NAME_MAX];
    uint8_t  d_type;         
    uint32_t d_size;        
} dirent;

typedef struct DIR DIR;

#ifdef __cplusplus
extern "C" {
#endif

DIR *opendir(const char *path);
int readdir(DIR *dirp, struct dirent *entry);
int closedir(DIR *dirp);

#ifdef __cplusplus
}
#endif
