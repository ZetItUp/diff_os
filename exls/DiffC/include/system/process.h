#pragma once

#include <syscall.h>

int process_spawn(const char *path, int argc, char **argv);
void process_exit(int code);
int process_wait(int pid, int* status);
