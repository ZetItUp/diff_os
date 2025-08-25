#include <stdio.h>
#include <system/threads.h>
#include <system/process.h>

int main(int argc, char **argv)
{
    printf("Process Testing Program\n");
    thread_sleep_ms(200);
    printf("Process Testing Ended\n");
    process_exit(0);

    return 0;
}
