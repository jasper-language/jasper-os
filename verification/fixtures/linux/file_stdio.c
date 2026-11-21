#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    int fd = creat("/tmp/jasper-file-stdio", 0600);
    FILE *file;

    if (fd < 0) return 10;
    file = fdopen(fd, "w");
    if (!file) return 11;
    if (fputs("fdopen-ok\n", file) < 0) return 12;
    if (fclose(file) != 0) return 13;
    puts("FILE_STDIO_OK");
    return 0;
}
