// syscall_file.c

#include "stdint.h"
#include "stddef.h"
#include "string.h"
#include "stdio.h"
#include "heap.h"
#include "console.h"
#include "interfaces.h"
#include "system/usercopy.h"
#include "system/process.h"
#include "system/path.h"
#include "diff.h"

#ifndef O_RDONLY
#define O_RDONLY 0x0000
#define O_WRONLY 0x0001
#define O_RDWR   0x0002
#define O_CREAT  0x0100
#define O_TRUNC  0x0200
#define O_APPEND 0x0400
#endif

#ifndef SEEK_SET
#define SEEK_SET 0
#endif
#ifndef SEEK_CUR
#define SEEK_CUR 1
#endif
#ifndef SEEK_END
#define SEEK_END 2
#endif

#define KERNEL_FILE_DESCRIPTOR_BASE 3
#define KERNEL_FILE_DESCRIPTOR_MAX  32
#define KERNEL_MAX_PATH            256
#define FILE_READ_CHUNK_BYTES      (16u * 1024u)   // skydda kmalloc och usercopy

// Kernel-level FD entry that maps to filesystem_* fd.
typedef struct
{
    uint8_t used;
    int     fs_fd;
    int     flags;
} kfile_t;

static kfile_t s_kfd[KERNEL_FILE_DESCRIPTOR_MAX];
static int     s_kfd_inited = 0;

// Ensure filesystem is ready and our table is initialized.
static int verify_fs_ready(void)
{
    if (!s_kfd_inited)
    {
        for (int i = 0; i < KERNEL_FILE_DESCRIPTOR_MAX; ++i)
        {
            s_kfd[i].used  = 0;
            s_kfd[i].fs_fd = -1;
            s_kfd[i].flags = 0;
        }
        s_kfd_inited = 1;
    }

    if (!file_table)
    {
        if (init_filesystem() != 0)
        {
            return -1;
        }
    }
    return 0;
}

// Open a file and return kernel-level fd (>=3) or -1.
int system_file_open(const char *abs_path, int oflags, int mode)
{
    (void)mode;

    if (verify_fs_ready() != 0)
        return -1;

    char upath[KERNEL_MAX_PATH];
    if (copy_string_from_user(upath, abs_path, sizeof(upath)) == -1)
        return -1;

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char norm[KERNEL_MAX_PATH];
    if (path_normalize(base, upath, norm, sizeof(norm)) != 0)
        return -1;

    // Try to open the file
    int fsfd = filesystem_open(norm);

    // If file doesn't exist and O_CREAT is set, create it
    if (fsfd < 0 && (oflags & O_CREAT))
    {
        // Create the file with initial size of 4KB
        if (filesystem_create(norm, 4096) == 0)
        {
            // Try to open again after creation
            fsfd = filesystem_open(norm);
        }
    }

    if (fsfd < 0)
        return -1;

    // Handle O_TRUNC flag - truncate file to 0 bytes
    if (oflags & O_TRUNC)
    {
        // For now, we don't support truncation
        // In a full implementation, you would reset file_size_bytes to 0
        // and optionally free sectors
    }

    // Allokera en kernel-fd och lås den mot underliggande fs_fd
    for (int i = 0; i < KERNEL_FILE_DESCRIPTOR_MAX; i++)
    {
        if (!s_kfd[i].used)
        {
            s_kfd[i].used  = 1;
            s_kfd[i].fs_fd = fsfd;
            s_kfd[i].flags = oflags;

            // O_APPEND - seek to end of file
            if (oflags & O_APPEND)
                (void)filesystem_lseek(fsfd, 0, SEEK_END);

            return KERNEL_FILE_DESCRIPTOR_BASE + i;
        }
    }

    // Slut på kfd-platser
    filesystem_close(fsfd);
    return -1;
}

// Close a kernel-level fd.
int system_file_close(int file_descriptor)
{
    if (file_descriptor < KERNEL_FILE_DESCRIPTOR_BASE)
        return 0; // stäng inte stdio

    int i = file_descriptor - KERNEL_FILE_DESCRIPTOR_BASE;
    if (i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_kfd[i].used)
        return -1;

    int fsfd = s_kfd[i].fs_fd;

    s_kfd[i].used  = 0;
    s_kfd[i].fs_fd = -1;
    s_kfd[i].flags = 0;

    if (fsfd >= 0 && filesystem_close(fsfd) != 0)
        return -1;

    return 0;
}

// Read from a file or stdin. Returns bytes read or -1.
long system_file_read(int file, void *buf, unsigned long count)
{
    // stdin
    if (file == 0)
    {
        uint8_t first = keyboard_getch();
        if (copy_to_user(buf, &first, 1) != 0)
            return -1;

        unsigned long n = 1;
        while (n < count)
        {
            uint8_t c;
            if (!keyboard_trygetch(&c))
                break;
            if (copy_to_user((uint8_t*)buf + n, &c, 1) != 0)
                break;
            n++;
        }
        return (long)n;
    }

    // stdout/stderr inte läsbara
    if (file == 1 || file == 2)
        return -1;

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;
    if (i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_kfd[i].used)
        return -1;

    if (count == 0)
        return 0;

    // Läs i hanterliga chunkar för att undvika stora allokeringar och
    // för att bättre hantera delvis mappade user-buffertar.
    unsigned long total = 0;

    // Allokera en engångs-bounce för kopiering till user
    size_t bounce_sz = (count < FILE_READ_CHUNK_BYTES) ? (size_t)count : (size_t)FILE_READ_CHUNK_BYTES;
    if (bounce_sz == 0)
        bounce_sz = 1;

    uint8_t *kbuf = (uint8_t*)kmalloc(bounce_sz);
    if (!kbuf)
        return -1;

    while (total < count)
    {
        unsigned long want = count - total;
        if (want > FILE_READ_CHUNK_BYTES)
            want = FILE_READ_CHUNK_BYTES;

        int r = filesystem_read(s_kfd[i].fs_fd, kbuf, (uint32_t)want);
        if (r <= 0)
        {
            // EOF (0) eller fel (<0)
            if (total == 0)
            {
                // inga bytes levererade – returnera felkoden eller 0
                kfree(kbuf);
                return (long)r;
            }
            break; // returnera det vi faktiskt hann leverera
        }

        if (copy_to_user((uint8_t*)buf + total, kbuf, (size_t)r) != 0)
        {
            // kunde inte kopiera allt till user – returnera det som faktiskt skrevs hittills
            kfree(kbuf);
            return (long)total;
        }

        total += (unsigned long)r;

        // Om vi läste mindre än vi bad om → sannolikt EOF, bryt
        if ((unsigned long)r < want)
            break;
    }

    kfree(kbuf);
    return (long)total;
}

// Change file position. Returns new position or -1.
long system_file_seek(int file, long offset, int whence)
{
    if (file < KERNEL_FILE_DESCRIPTOR_BASE)
    {
        // tillåt ftell på std-streams
        if (whence == SEEK_CUR && offset == 0)
            return 0;
        return -1;
    }

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;
    if (i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_kfd[i].used)
        return -1;

    int32_t np = filesystem_lseek(s_kfd[i].fs_fd, (int32_t)offset, whence);
    if (np < 0)
        return -1;

    return (long)np;
}

// Write to file or stdout/stderr.
long system_file_write(int file, const void *buf, unsigned long count)
{
    // stdout/stderr - route through TTY for terminal output capture
    if (file == 1 || file == 2)
    {
        process_t *proc = process_current();
        int tty_enabled = 1;
        if (proc && !proc->tty_output_enabled)
        {
            tty_enabled = 0;
        }

        // Copy to kernel buffer and call tty_write for output capture
        char kbuf[256];
        unsigned long written = 0;

        while (written < count)
        {
            unsigned long chunk = count - written;
            if (chunk > sizeof(kbuf))
                chunk = sizeof(kbuf);

            if (copy_from_user(kbuf, (const uint8_t*)buf + written, chunk) != 0)
                return (long)written;

            if (tty_enabled)
            {
                // Route through TTY - this stores in output buffer AND prints
                int rc = tty_write(kbuf, (unsigned)chunk);
                if (rc <= 0)
                {
                    // TTY not available, fall back to direct console output
                    for (unsigned long i = 0; i < chunk; i++)
                        putch(kbuf[i]);
                }
            }

            written += chunk;
        }

        return (long)count;
    }

    // stdin not writable
    if (file == 0)
        return -1;

    // File write
    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;
    if (i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_kfd[i].used)
        return -1;

    // Check if file was opened with write permissions
    int flags = s_kfd[i].flags;
    if ((flags & O_WRONLY) == 0 && (flags & O_RDWR) == 0)
        return -1; // File not opened for writing

    if (count == 0)
        return 0;

    // Write in chunks similar to read
    unsigned long total = 0;

    // Allocate bounce buffer for copying from user
    size_t bounce_sz = (count < FILE_READ_CHUNK_BYTES) ? (size_t)count : (size_t)FILE_READ_CHUNK_BYTES;
    if (bounce_sz == 0)
        bounce_sz = 1;

    uint8_t *kbuf = (uint8_t*)kmalloc(bounce_sz);
    if (!kbuf)
        return -1;

    while (total < count)
    {
        unsigned long want = count - total;
        if (want > FILE_READ_CHUNK_BYTES)
            want = FILE_READ_CHUNK_BYTES;

        // Copy from user buffer to kernel buffer
        if (copy_from_user(kbuf, (const uint8_t*)buf + total, (size_t)want) != 0)
        {
            kfree(kbuf);
            return (total > 0) ? (long)total : -1;
        }

        // Write to filesystem
        int r = filesystem_write(s_kfd[i].fs_fd, kbuf, (uint32_t)want);
        if (r <= 0)
        {
            // Error or no space
            if (total == 0)
            {
                kfree(kbuf);
                return (long)r;
            }
            break; // Return what we managed to write
        }

        total += (unsigned long)r;

        // If we wrote less than we asked for, stop
        if ((unsigned long)r < want)
            break;
    }

    kfree(kbuf);
    return (long)total;
}

// Stat by path. Returns 0 on success, -1 on error.
int system_file_stat(const char *abs_path, filesystem_stat_t *user_st)
{
    if (verify_fs_ready() != 0)
        return -1;

    char upath[KERNEL_MAX_PATH];
    if (copy_string_from_user(upath, abs_path, sizeof(upath)) == -1)
        return -1;

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char norm[KERNEL_MAX_PATH];
    if (path_normalize(base, upath, norm, sizeof(norm)) != 0)
        return -1;

    filesystem_stat_t st;
    if (filesystem_stat(norm, &st) != 0)
        return -1;

    if (copy_to_user(user_st, &st, sizeof(st)) != 0)
        return -1;

    return 0;
}

// fstat by fd. Returns 0 on success, -1 on error.
int system_file_fstat(int file, filesystem_stat_t *user_st)
{
    if (file < KERNEL_FILE_DESCRIPTOR_BASE)
    {
        filesystem_stat_t st;
        st.size = 0;
        if (copy_to_user(user_st, &st, sizeof(st)) != 0)
            return -1;
        return 0;
    }

    int i = file - KERNEL_FILE_DESCRIPTOR_BASE;
    if (i < 0 || i >= KERNEL_FILE_DESCRIPTOR_MAX || !s_kfd[i].used)
        return -1;

    filesystem_stat_t st;
    if (filesystem_fstat(s_kfd[i].fs_fd, &st) != 0)
        return -1;

    if (copy_to_user(user_st, &st, sizeof(st)) != 0)
        return -1;

    return 0;
}

// Delete a file. Returns 0 on success, -1 on error.
int system_file_delete(const char *abs_path)
{
    if (verify_fs_ready() != 0)
        return -1;

    char upath[KERNEL_MAX_PATH];
    if (copy_string_from_user(upath, abs_path, sizeof(upath)) == -1)
        return -1;

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char norm[KERNEL_MAX_PATH];
    if (path_normalize(base, upath, norm, sizeof(norm)) != 0)
        return -1;

    return filesystem_delete(norm);
}

// Rename a file. Returns 0 on success, -1 on error.
int system_file_rename(const char *old_path, const char *new_path)
{
    // For now, we'll implement this as a copy + delete
    // A more efficient implementation would update the file table entry directly
    if (verify_fs_ready() != 0)
        return -1;

    char uold[KERNEL_MAX_PATH];
    char unew[KERNEL_MAX_PATH];
    if (copy_string_from_user(uold, old_path, sizeof(uold)) == -1)
        return -1;
    if (copy_string_from_user(unew, new_path, sizeof(unew)) == -1)
        return -1;

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char norm_old[KERNEL_MAX_PATH];
    char norm_new[KERNEL_MAX_PATH];
    if (path_normalize(base, uold, norm_old, sizeof(norm_old)) != 0)
        return -1;
    if (path_normalize(base, unew, norm_new, sizeof(norm_new)) != 0)
        return -1;

    return filesystem_rename(norm_old, norm_new);
}

// Read a symlink target. Returns target length on success, -1 on error.
int system_file_readlink(const char *abs_path, char *buf, size_t bufsize)
{
    if (verify_fs_ready() != 0)
        return -1;

    if (!abs_path || !buf || bufsize == 0)
        return -1;

    char upath[KERNEL_MAX_PATH];
    if (copy_string_from_user(upath, abs_path, sizeof(upath)) == -1)
        return -1;

    process_t *proc = process_current();
    const char *base = process_cwd_path(proc);
    char norm[KERNEL_MAX_PATH];
    if (path_normalize(base, upath, norm, sizeof(norm)) != 0)
        return -1;

    char target[MAX_SYMLINK_TARGET];
    int len = filesystem_readlink(norm, target, sizeof(target));
    if (len < 0)
        return -1;

    size_t copy_len = (size_t)len + 1;
    if (copy_len > bufsize)
        copy_len = bufsize;

    if (copy_to_user(buf, target, copy_len) != 0)
        return -1;

    return len;
}
