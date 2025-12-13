#pragma once

#include <stdint.h>
#include <stddef.h>

/*
 * Simple helper API to read embedded resources from a DEX file.
 * All returned strings are heap-allocated; caller must free().
 */

/* Fetch a string resource by key (e.g., "APPLICATION_TITLE", "WINDOW_TITLE", or any STRING key). */
char *diffdex_get_resource_string(const char *dex_path, const char *key);

/* Fetch a u32 resource by key (e.g., "APPLICATION_VERSION_MAJOR"). Returns 0 on success. */
int diffdex_get_resource_u32(const char *dex_path, const char *key, uint32_t *out);

/* Convenience wrappers */
char *diffdex_get_application_title(const char *dex_path);
char *diffdex_get_window_title(const char *dex_path);
int diffdex_get_application_version(const char *dex_path, uint32_t *major, uint32_t *minor);
