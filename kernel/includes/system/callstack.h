#pragma once

#include "stdint.h"

#ifndef CALLSTACK_MAX_FRAMES
#define CALLSTACK_MAX_FRAMES 12
#endif

int callstack_capture_kernel(uint32_t ebp, uint32_t eip, uint32_t *out_frames, int max_frames);
int callstack_capture_user(uint32_t ebp, uint32_t eip, uint32_t *out_frames, int max_frames);
