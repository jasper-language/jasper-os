#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat st;
    int pipe_fds[2];
    int socket_fds[2];
    int fd = creat("/tmp/jasper-file-stdio", 0600);
    FILE *file;

    if (fstat(STDOUT_FILENO, &st) != 0 || !S_ISCHR(st.st_mode)) return 14;
    if (pipe(pipe_fds) != 0 ||
        fstat(pipe_fds[0], &st) != 0 || !S_ISFIFO(st.st_mode) ||
        fstat(pipe_fds[1], &st) != 0 || !S_ISFIFO(st.st_mode)) return 17;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds) != 0 ||
        fstat(socket_fds[0], &st) != 0 || !S_ISSOCK(st.st_mode) ||
        fstat(socket_fds[1], &st) != 0 || !S_ISSOCK(st.st_mode)) return 18;
    errno = 0;
    if (fstat(-1, &st) != -1 || errno != EBADF) return 15;
    errno = 0;
    if (fstat(99, &st) != -1 || errno != EBADF) return 16;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(socket_fds[0]);
    close(socket_fds[1]);
    if (fd < 0) return 10;
    file = fdopen(fd, "w");
    if (!file) return 11;
    if (fputs("fdopen-ok\n", file) < 0) return 12;
    if (fclose(file) != 0) return 13;
    puts("FILE_STDIO_OK stdio_stat=true pipe_stat=true socket_stat=true");
    return 0;
}
