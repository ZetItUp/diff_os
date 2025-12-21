#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * DiffRuntime - Program Execution Library
 *
 * Provides high-level APIs for:
 * - Program resolution with priority-based lookup
 * - Process spawning (child processes or independent processes)
 * - PATH environment variable management
 */

/* Maximum path length */
#define RT_MAX_PATH     256
#define RT_MAX_NAME     64
#define RT_MAX_PATHS    16

/* Spawn flags */
#define RT_SPAWN_CHILD      0x00    /* Spawn as child process (default) */
#define RT_SPAWN_DETACHED   0x01    /* Spawn as independent process */
#define RT_SPAWN_WAIT       0x02    /* Wait for process to complete */

/* Resolution flags - control search order */
#define RT_RESOLVE_CWD      0x01    /* Search current directory */
#define RT_RESOLVE_CMDMAP   0x02    /* Search commands.map */
#define RT_RESOLVE_PATH     0x04    /* Search PATH directories */
#define RT_RESOLVE_ALL      0x07    /* Search all (default) */

/* Result codes */
#define RT_OK               0
#define RT_ERR_NOT_FOUND    (-1)
#define RT_ERR_NO_MEMORY    (-2)
#define RT_ERR_SPAWN_FAIL   (-3)
#define RT_ERR_INVALID      (-4)

/*
 * Initialize the runtime library.
 * Loads commands.map and initializes PATH.
 *
 * @param commands_map_path  Path to commands.map file (NULL for default)
 * @return RT_OK on success, error code otherwise
 */
int rt_init(const char *commands_map_path);

/*
 * Shutdown the runtime library.
 * Frees allocated resources.
 */
void rt_shutdown(void);

/*
 * Resolve a program name to its full path.
 * Search order (controlled by flags):
 *   1. Current working directory (if RT_RESOLVE_CWD)
 *   2. commands.map lookup (if RT_RESOLVE_CMDMAP)
 *   3. PATH directories (if RT_RESOLVE_PATH)
 *
 * @param name      Program name (e.g., "ls" or "/programs/ls/ls.dex")
 * @param out_path  Buffer to receive resolved path
 * @param out_size  Size of output buffer
 * @param flags     RT_RESOLVE_* flags (0 for default = RT_RESOLVE_ALL)
 * @return RT_OK if found, RT_ERR_NOT_FOUND otherwise
 */
int rt_resolve(const char *name, char *out_path, size_t out_size, int flags);

/*
 * Execute a program.
 * Resolves the program name and spawns it.
 *
 * @param name   Program name or path
 * @param argc   Number of arguments
 * @param argv   Argument array (can be NULL if argc == 0)
 * @param flags  RT_SPAWN_* flags
 * @return Process ID on success, negative error code on failure
 */
int rt_exec(const char *name, int argc, char **argv, int flags);

/*
 * Execute a program and wait for completion.
 * Convenience wrapper for rt_exec with RT_SPAWN_WAIT.
 *
 * @param name   Program name or path
 * @param argc   Number of arguments
 * @param argv   Argument array (can be NULL if argc == 0)
 * @param status Pointer to receive exit status (can be NULL)
 * @return RT_OK on success, error code on failure
 */
int rt_exec_wait(const char *name, int argc, char **argv, int *status);

/*
 * Get the current PATH string.
 * Returns a colon-separated list of directories.
 *
 * @param out_path  Buffer to receive PATH string
 * @param out_size  Size of output buffer
 * @return RT_OK on success, error code on failure
 */
int rt_get_path(char *out_path, size_t out_size);

/*
 * Set the PATH string.
 * Replaces the current PATH with a new colon-separated list.
 *
 * @param path  New PATH string (colon-separated directories)
 * @return RT_OK on success, error code on failure
 */
int rt_set_path(const char *path);

/*
 * Append a directory to PATH.
 *
 * @param dir  Directory to append
 * @return RT_OK on success, error code on failure
 */
int rt_append_path(const char *dir);

/*
 * Prepend a directory to PATH.
 *
 * @param dir  Directory to prepend
 * @return RT_OK on success, error code on failure
 */
int rt_prepend_path(const char *dir);

/*
 * Check if a file exists and is executable.
 *
 * @param path  Full path to check
 * @return true if file exists, false otherwise
 */
bool rt_file_exists(const char *path);
