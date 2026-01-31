#include <runtime/process.h>
#include <syscall.h>

int rt_process_list(process_list_entry_t *entries, int max_entries)
{
    if (!entries || max_entries <= 0)
    {
        return -1;
    }

    return system_process_list(entries, max_entries);
}

int rt_process_get_name(int pid, char *buffer, size_t buffer_len)
{
    if (!buffer || buffer_len == 0)
    {
        return -1;
    }

    return system_process_get_name(pid, buffer, buffer_len);
}
