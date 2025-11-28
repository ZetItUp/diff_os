#include "debug.h"
#include "system.h"
#include "stdio.h"
#include "stdint.h"
#include "console.h"

#ifdef DIFF_DEBUG
/* Disable noisy paging debug by default; enable manually with debug_enable() if needed. */
uint32_t g_debug_mask = DEBUG_AREA_GENERIC | DEBUG_AREA_EXL;
#else
/* Always keep EXL debug enabled to aid tracing library loads. */
uint32_t g_debug_mask = 0;
#endif

uint32_t g_ss_entry = 0;
uint32_t g_ss_remaining = 0;
uint32_t g_ss_arg_a = 0;
uint32_t g_ss_arg_b = 0;

void debug_request_single_step(uint32_t entry_va, uint32_t steps)
{
    g_ss_entry = entry_va;
    g_ss_remaining = steps;
    g_ss_arg_a = 0;
    g_ss_arg_b = 0;
    DDBG("[SSTEP] request entry=0x%08x steps=%u\n", entry_va, steps);
}

int debug_prepare_single_step(uint32_t entry_eip)
{
    DDBG("[SSTEP] prepare check entry=0x%08x (target=0x%08x remaining=%u, A=0x%08x B=0x%08x)\n",
         entry_eip, g_ss_entry, g_ss_remaining, g_ss_arg_a, g_ss_arg_b);
    if (!g_ss_remaining || entry_eip != g_ss_entry)
        return 0;
    DDBG("[SSTEP] prepare entry=0x%08x\n", entry_eip);
    return 1;
}

int debug_handle_single_step(struct stack_frame *frame)
{
    if (!g_ss_remaining)
    {
        frame->eflags &= ~(1u << 8); // clear TF
        g_ss_entry = 0;
        return 1;
    }

    DDBG("[SSTEP] EIP=%08x bytes:", frame->eip);
    const uint8_t *p = (const uint8_t*)(uintptr_t)frame->eip;
    for (int i = 0; i < 8; ++i)
    {
        DDBG(" %02x", p[i]);
    }
    DDBG("\n");

    if (--g_ss_remaining == 0)
    {
        frame->eflags &= ~(1u << 8); // clear TF
        DDBG("[SSTEP] done\n");
        g_ss_entry = 0;

        if (!console_is_vbe_active())
        {
            console_use_vbe(1);
            console_flush_log();
        }
    }
    return 1;
}
