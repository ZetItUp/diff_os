#include <system/command_registry.h>
#include <system/process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <dirent.h>
#include <syscall.h>
#include <console.h>

static const char *g_shell_name   = "Different Terminal";
static const unsigned g_ver_major = 1;
static const unsigned g_ver_minor = 0;

static int g_last_status = 0;
static char g_cwd[256] = "/";

static int bi_help(int argc, char **argv)
{
    (void)argc; 
    (void)argv;
    
    puts(" Available commands:");
    puts("--------------------------------------------");
    puts(" cd    \t- Change current directory");
    puts(" help  \t- List built-in commands");
    puts(" echo  \t- Print its arguments");
    puts(" ver   \t- Show shell version");
    puts(" exit  \t- Exit the shell");

    return 0;
}

static int bi_echo(int argc, char **argv)
{
    uint8_t fg_tmp = 0;
    console_get_fgcolor(&fg_tmp);
    console_set_fgcolor(CONSOLE_COLOR_CYAN);

    for (int i = 1; i < argc; i++) 
    {
        if (i > 1)
        {
            putchar(' ');
        }

        printf("%s", argv[i]);
    }

    console_set_fgcolor(fg_tmp);
    putchar('\n');
    
    return 0;
}

static int bi_ver(int argc, char **argv)
{
    (void)argc; 
    (void)argv;
    
    printf("%s (Version %u.%u)\n", g_shell_name, g_ver_major, g_ver_minor);
    
    return 0;
}

static int bi_exit(int argc, char **argv)
{
    (void)argc; 
    (void)argv;
    
    exit(0);
    
    return 0;
}

static int bi_cd(int argc, char **argv)
{
    const char *arg = (argc < 2 || !argv[1] || !argv[1][0]) ? "/" : argv[1];

    if (chdir(arg) != 0)
    {
        printf("Directory %s does not exist.\n", arg);
        return -1;
    }

    if (!getcwd(g_cwd, sizeof(g_cwd)))
    {
        strncpy(g_cwd, "/", sizeof(g_cwd) - 1);
        g_cwd[sizeof(g_cwd) - 1] = '\0';
    }

    return 0;
}

static int tokenize(char *line, char **argv, int maxv)
{
    int argc = 0;
    char *s = line;

    size_t n = strlen(s);

    if (n && (s[n-1] == '\n' || s[n-1] == '\r'))
    {
        s[--n] = 0;
    }

    while (*s && argc < maxv) 
    {
        while (*s == ' ' || *s == '\t')
        {
            s++;
        }

        if (!*s)
        {
            break;
        }

        argv[argc++] = s;
        
        while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
        {
            s++;
        }
        
        if (!*s)
        {
            break;
        }

        *s++ = 0;
    }
    
    return argc;
}

static int run_builtin(int argc, char **argv)
{
    if (argc == 0)
    {
        return 0;
    }

    if (strcmp(argv[0], "cd") == 0)
    {
        return bi_cd(argc, argv);
    }
    
    if (strcmp(argv[0], "help") == 0) 
    {
        return bi_help(argc, argv);
    }
    
    if (strcmp(argv[0], "echo") == 0)
    {
        return bi_echo(argc, argv);
    }
    
    if (strcmp(argv[0], "ver")  == 0)
    {
        return bi_ver(argc, argv);
    }
    
    if (strcmp(argv[0], "exit") == 0)
    {
        return bi_exit(argc, argv);
    }

    return 1;
}

static int run_external(int argc, char **argv)
{
    if (argc == 0) {
        return 0;
    }

    // argv[0] = kommandonamn; slå upp .dex-sökväg i kommandoregistret
    const char *path = cmdreg_lookup(argv[0]);
    if (!path) {
        printf("Unknown command: %s\n", argv[0]);
        return -1;
    }

    // Skicka argv som det är: argv[0] är kommandonamnet.
    int pid = process_spawn(path, argc, argv);

    if (pid < 0) {
        printf("[SYSTEM] Could not start %s\n", path);
        return -1;
    }

    int status = 0;
    int w = process_wait(pid, &status);
    if (w < 0) {
        printf("[SYSTEM] Failed to wait for process %d\n", pid);
        return -1;
    }

    g_last_status = status;
    if (status != 0) {
        printf("%s exited with %d\n", argv[0], status);
    }
    return status;
}


int main(void)
{
    if (!cmdreg_init("/system/commands.map")) {
        puts("[CRITICAL ERROR] Unable to initialize command registry!");
        /* Om kommandoregistret inte finns är det meningslöst att fortsätta. */
        return 127;
    }

    if (!getcwd(g_cwd, sizeof(g_cwd)))
    {
        strncpy(g_cwd, "/", sizeof(g_cwd) - 1);
        g_cwd[sizeof(g_cwd) - 1] = '\0';
    }

    /* Avbufferad stdout så prompten verkligen syns direkt */

    printf("\n%s (Version %u.%u)\n\n", g_shell_name, g_ver_major, g_ver_minor);

    char *line = NULL;
    size_t cap = 0;

    for (;;) 
    {
        printf("%s> ", g_cwd);
        fflush(stdout); /* säkerställ prompten syns även om stdio inte är helt avbuffrat */

        /*int x, y;
        console_getxy(&x, &y);
        console_floor_set(x, y);
        */
        ssize_t n = getline(&line, &cap);
        // console_floor_clear();

        if (n <= 0)
        {
            /* Inget att läsa just nu -> ge schemaläggaren CPU:n en stund */
            continue;
        }

        char *argv[16];
        int argc = tokenize(line, argv, 16);
        
        if (argc == 0)
        {
            continue;
        }

        int rc = run_builtin(argc, argv);
        if (rc == 1) 
        {
            run_external(argc, argv);
        }

        printf("\n");
    }
}
