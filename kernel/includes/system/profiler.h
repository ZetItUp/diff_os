#pragma once

#include "stdint.h"
#include "stddef.h"
#include "dirent.h"

// Maximum number of unique sample addresses to track
#define PROFILER_MAX_SAMPLES 4096

// Maximum symbols per process for profiling (DEX + all EXLs)
#define PROFILER_MAX_SYMBOLS 4096

// Maximum symbol name length
#define PROFILER_MAX_SYMBOL_NAME 64

// Maximum library name length
#define PROFILER_MAX_LIB_NAME 32

// Profiler sample entry
typedef struct
{
    uint32_t address;
    uint32_t count;
} profiler_sample_t;

// Symbol entry for address resolution
typedef struct
{
    uint32_t address;
    char name[PROFILER_MAX_SYMBOL_NAME];
    char library[PROFILER_MAX_LIB_NAME];
} profiler_symbol_t;

// Profiler state
typedef struct
{
    int active;
    int target_pid;
    uint32_t image_base;
    uint32_t total_samples;
    char target_name[NAME_MAX];

    // Sample histogram
    profiler_sample_t samples[PROFILER_MAX_SAMPLES];
    int sample_count;

    // Symbol table for resolution
    profiler_symbol_t symbols[PROFILER_MAX_SYMBOLS];
    int symbol_count;
} profiler_state_t;

// Initialize profiler subsystem
void profiler_init(void);

// Start profiling a process
// pid: process to profile (-1 for current)
int profiler_start(int pid);

// Stop profiling
int profiler_stop(void);

// Record a sample (called from timer interrupt)
void profiler_record_sample(uint32_t eip, int pid);

// Dump results to serial in CSV format
int profiler_dump_csv(void);

// Check if profiler is active
int profiler_is_active(void);

// Get profiler target pid
int profiler_target_pid(void);

// Load symbols from a DEX/EXL for the current profile target
int profiler_load_symbols(const void *dex_data, size_t dex_size, uint32_t image_base, const char *library_name);

// Clear all loaded symbols
void profiler_clear_symbols(void);
