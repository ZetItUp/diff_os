#pragma once

#include "stdint.h"
#include "system.h"
#include "stdio.h"

#define DEBUG_AREA_GENERIC (1u << 0)
#define DEBUG_AREA_PAGING  (1u << 1)
#define DEBUG_AREA_EXL     (1u << 2)

extern uint32_t g_debug_mask;

static inline void debug_enable(uint32_t mask)
{
    g_debug_mask |= mask;
}

static inline void debug_disable(uint32_t mask)
{
    g_debug_mask &= ~mask;
}

#define DDBG(...) do { if (g_debug_mask & DEBUG_AREA_GENERIC) printf(__VA_ARGS__); } while (0)
#define DDBG_IF(mask, ...) do { if (g_debug_mask & (mask)) printf(__VA_ARGS__); } while (0)

void debug_request_single_step(uint32_t entry_va, uint32_t steps);
int  debug_prepare_single_step(uint32_t entry_va);
int  debug_handle_single_step(struct stack_frame *frame);

extern uint32_t g_ss_entry;
extern uint32_t g_ss_remaining;
extern uint32_t g_ss_arg_a;
extern uint32_t g_ss_arg_b;
