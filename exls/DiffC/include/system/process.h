#pragma once

#include <syscall.h>

int process_spawn(const char *path, int argc, char **argv);
void process_exit(int code);
int process_wait(int pid, int* status);
int process_get_resources(int pid, void *buffer, unsigned int buffer_len); // returns size copied or size needed if buffer_len==0
