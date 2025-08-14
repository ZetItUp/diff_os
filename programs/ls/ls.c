#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

enum
{
    TYPE_W = 12,
    SIZE_W = 10,
    NAME_W = 20
};

static void hr(char ch)
{
    int width = 1 + TYPE_W + 1 + SIZE_W + 2 + NAME_W + 4;
    
    for (int i = 0; i < width; i++) 
    { 
        putchar(ch); 
    }
    
    putchar('\n');
}

int main(int argc, char *argv[])
{
    const char *path = (argc > 1 && argv[1] && argv[1][0]) ? argv[1] : ".";

    DIR *d = opendir(path);

    if(!d)
    {
        printf("ls: There is no directory %s!\n", path);

        return 1;
    }

    struct dirent ent;

    const char *tmp_path = path;

    while(*tmp_path == '/' || *tmp_path == '.')
    {
        tmp_path++;
    }

    printf("Content of %s/\n", tmp_path);
    hr('=');
    printf(" %-12s %10s  %s\n", "Type", "Size", "Name");
    hr('-');

    while(1)
    {
        int read = readdir(d, &ent);

        if(read > 0)
        {
            break;
        }
        if(read < 0)
        {
            printf("ls: Read Error!\n");
            closedir(d);

            return 1;
        }
        
        if(ent.d_type == DT_DIR)
        {
            const char *dir_name = ent.d_name;

            while(*dir_name == '/')
            {
                dir_name++;
            }
            
            printf(" %-12s %10u  %s/\n", "<DIRECTORY>", (unsigned)ent.d_size, dir_name);
        }
        else if(ent.d_type == DT_REG)
        {
            printf(" %-12s %10u  %s/\n", "<FILE>", (unsigned)ent.d_size, ent.d_name);
        }
    }

    hr('-');
    closedir(d);

    return 0;
}
