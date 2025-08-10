#pragma once

#include "stdint.h"
#include "diff.h"

struct stack_frame
{
    uint32_t gs, fs, es, ds;
    uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
    uint32_t int_no, err_code;
    uint32_t eip, cs, eflags, useresp, ss;
};

typedef struct system_info
{
    uint32_t ram_mb;
} sys_info_t;

char *find_shell_path(const FileTable *table, const char *cfg_path);
