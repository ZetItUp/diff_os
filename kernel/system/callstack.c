#include "system/callstack.h"
#include "paging.h"
#include "system/usercopy.h"
#include "stddef.h"

static int kernel_read_u32(uint32_t addr, uint32_t *out)
{
    if (addr < KERNEL_BASE)
    {
        return -1;
    }

    if (!page_is_present(addr) || !page_is_present(addr + sizeof(uint32_t) - 1))
    {
        return -1;
    }

    *out = *(const uint32_t *)(uintptr_t)addr;

    return 0;
}

static int user_read_u32(uint32_t addr, uint32_t *out)
{
    if (!is_user_addr(addr))
    {
        return -1;
    }

    if (paging_check_user_range(addr, sizeof(uint32_t)) != 0)
    {
        return -1;
    }

    if (copy_from_user(out, (const void *)(uintptr_t)addr, sizeof(uint32_t)) != 0)
    {
        return -1;
    }

    return 0;
}

static int callstack_capture(uint32_t ebp,
                             uint32_t eip,
                             uint32_t *out_frames,
                             int max_frames,
                             int (*read_u32)(uint32_t addr, uint32_t *out),
                             int (*addr_ok)(uint32_t addr))
{
    if (!out_frames || max_frames <= 0 || !read_u32 || !addr_ok)
    {
        return 0;
    }

    int count = 0;
    out_frames[count++] = eip;

    uint32_t bp = ebp;
    for (int i = 0; i < max_frames - 1; ++i)
    {
        if (bp == 0 || (bp & 0x3u) != 0 || !addr_ok(bp))
        {
            break;
        }

        uint32_t next_bp = 0;
        uint32_t ret_addr = 0;

        if (read_u32(bp, &next_bp) != 0)
        {
            break;
        }

        if (read_u32(bp + 4, &ret_addr) != 0)
        {
            break;
        }

        if (ret_addr == 0)
        {
            break;
        }

        out_frames[count++] = ret_addr;

        if (next_bp <= bp)
        {
            break;
        }

        bp = next_bp;

        if (count >= max_frames)
        {
            break;
        }
    }

    return count;
}

static int kernel_addr_ok(uint32_t addr)
{
    return addr >= KERNEL_BASE;
}

static int user_addr_ok(uint32_t addr)
{
    return is_user_addr(addr);
}

int callstack_capture_kernel(uint32_t ebp, uint32_t eip, uint32_t *out_frames, int max_frames)
{
    return callstack_capture(ebp, eip, out_frames, max_frames, kernel_read_u32, kernel_addr_ok);
}

int callstack_capture_user(uint32_t ebp, uint32_t eip, uint32_t *out_frames, int max_frames)
{
    return callstack_capture(ebp, eip, out_frames, max_frames, user_read_u32, user_addr_ok);
}
