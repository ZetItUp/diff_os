#include <stdio.h>
#include <syscall.h>

int main(void)
{
    printf("=== Simple Write Test ===\n");

    printf("Opening file...\n");
    int fd = system_open("/testfile.txt", O_CREAT | O_WRONLY, 0);

    if (fd < 0)
    {
        printf("Failed to open\n");
        return 1;
    }

    printf("File opened, fd=%d\n", fd);

    const char *msg = "Test\n";
    printf("Writing...\n");

    int written = system_write(fd, msg, 5);

    printf("Write returned %d\n", written);

    system_close(fd);
    printf("Done!\n");

    return 0;
}
