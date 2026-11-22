#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat st;
    int fd = creat("/tmp/jasper-file-stdio", 0600);
    FILE *file;

    if (fstat(STDOUT_FILENO, &st) != 0 || !S_ISCHR(st.st_mode)) return 14;
    errno = 0;
    if (fstat(-1, &st) != -1 || errno != EBADF) return 15;
    errno = 0;
    if (fstat(99, &st) != -1 || errno != EBADF) return 16;
    if (fd < 0) return 10;
    file = fdopen(fd, "w");
    if (!file) return 11;
    if (fputs("fdopen-ok\n", file) < 0) return 12;
    if (fclose(file) != 0) return 13;
    puts("FILE_STDIO_OK stdio_stat=true");
    return 0;
}
