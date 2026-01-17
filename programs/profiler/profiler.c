// Profiler control program for DiffOS
// Runs a target program and profiles it, dumping results to serial

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>

static void print_usage(void)
{
    printf("Usage: profiler <program> [args...]\n");
    printf("\n");
    printf("Runs the specified program while profiling it.\n");
    printf("Results are output as CSV to the serial port.\n");
    printf("\n");
    printf("Example: profiler /programs/diffwm/diffwm.dex\n");
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        print_usage();

        return 1;
    }

    const char *target_program = argv[1];

    // Build arguments for child process
    int child_argc = argc - 1;
    char **child_argv = &argv[1];

    printf("[profiler] Spawning: %s\n", target_program);

    // Spawn the target process
    int child_pid = system_process_spawn(target_program, child_argc, child_argv);
    if (child_pid < 0)
    {
        printf("[profiler] Failed to spawn: %s\n", target_program);

        return 1;
    }

    printf("[profiler] Started PID %d, enabling profiler...\n", child_pid);

    // Start profiling the child process
    if (system_profiler_start(child_pid) < 0)
    {
        printf("[profiler] Failed to start profiler\n");
        system_wait_pid(child_pid, NULL);

        return 1;
    }

    printf("[profiler] Profiling active. Waiting for process to exit...\n");
    printf("[profiler] Press Ctrl+C to stop profiling early.\n");

    // Wait for child to exit
    int exit_code = 0;
    system_wait_pid(child_pid, &exit_code);

    printf("[profiler] Process exited with code %d\n", exit_code);

    // Stop profiler and dump results
    system_profiler_stop();

    printf("[profiler] Dumping profile data to serial...\n");
    system_profiler_dump();

    printf("[profiler] Done. Check serial.log for CSV data.\n");

    return 0;
}
