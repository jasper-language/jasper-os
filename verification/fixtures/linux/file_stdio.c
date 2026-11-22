#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    struct stat st;
    mode_t old_mask;
    int mode_fd;
    char io_buffer[4] = {0};
    char cwd[PATH_MAX];
    int pipe_fds[2];
    int socket_fds[2];
    int cwd_fd;
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
    old_mask = umask(0027);
    mode_fd = open("/tmp/jasper-file-mode", O_CREAT | O_RDWR | O_CLOEXEC, 0666);
    umask(old_mask);
    if (mode_fd < 0) return 19;
    if (fstat(mode_fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (st.st_mode & 0777) != 0640 || st.st_nlink != 1) return 20;
    if ((fcntl(mode_fd, F_GETFL) & O_ACCMODE) != O_RDWR) return 21;
    if ((fcntl(mode_fd, F_GETFD) & FD_CLOEXEC) == 0) return 22;
    if (write(mode_fd, "abc", 3) != 3 || fstat(mode_fd, &st) != 0 ||
        st.st_size != 3) return 23;
    if (pwrite(mode_fd, "XYZ", 3, 8) != 3 ||
        fstat(mode_fd, &st) != 0 || st.st_size != 11) return 26;
    if (lseek(mode_fd, 0, SEEK_CUR) != 3) return 27;
    if (pread(mode_fd, io_buffer, 3, 8) != 3 ||
        memcmp(io_buffer, "XYZ", 3) != 0 ||
        lseek(mode_fd, 0, SEEK_CUR) != 3) return 28;
    errno = 0;
    if (pwrite(mode_fd, "q", 1, -1) != -1 || errno != EINVAL) return 29;
    errno = 0;
    if (pread(mode_fd, (void *)1, 1, 0) != -1 || errno != EFAULT) return 30;
    errno = 0;
    if (pread(99, io_buffer, 1, 0) != -1 || errno != EBADF) return 31;
    errno = 0;
    if (pwrite(99, "q", 1, 0) != -1 || errno != EBADF) return 32;
    if (close(mode_fd) != 0) return 24;
    errno = 0;
    if (open("/tmp/jasper-missing-file", O_RDONLY) != -1 ||
        errno != ENOENT) return 25;
    if (mkdir("/tmp/jasper-cwd", 0700) != 0 ||
        chdir("/tmp/jasper-cwd") != 0 ||
        !getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/tmp/jasper-cwd") != 0) {
        return 33;
    }
    cwd_fd = open(".", O_RDONLY | O_DIRECTORY);
    if (cwd_fd < 0 || chdir("/") != 0 || fchdir(cwd_fd) != 0 ||
        !getcwd(cwd, sizeof(cwd)) || strcmp(cwd, "/tmp/jasper-cwd") != 0) {
        return 34;
    }
    if (rmdir("/tmp/jasper-cwd") != 0) return 35;
    errno = 0;
    if (getcwd(cwd, sizeof(cwd)) != NULL || errno != ENOENT) return 36;
    errno = 0;
    if (open("relative-missing", O_RDONLY) != -1 || errno != ENOENT) return 37;
    if (chdir("/") != 0) return 38;
    errno = 0;
    if (chdir("/tmp/jasper-cwd") != -1 || errno != ENOENT) return 39;
    errno = 0;
    if (fchdir(99) != -1 || errno != EBADF) return 40;
    if (close(cwd_fd) != 0) return 41;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(socket_fds[0]);
    close(socket_fds[1]);
    if (fd < 0) return 10;
    file = fdopen(fd, "w");
    if (!file) return 11;
    if (fputs("fdopen-ok\n", file) < 0) return 12;
    if (fclose(file) != 0) return 13;
    puts("FILE_STDIO_OK stdio_stat=true pipe_stat=true socket_stat=true file_status=true positioned_io=true cwd_status=true");
    return 0;
}
