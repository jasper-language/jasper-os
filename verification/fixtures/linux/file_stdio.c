#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t interrupted;

static void handle_signal(int signal_number)
{
    (void)signal_number;
    interrupted = 1;
}

int main(void)
{
    struct stat st;
    mode_t old_mask;
    int mode_fd;
    char io_buffer[4] = {0};
    char cwd[PATH_MAX];
    struct flock lock;
    struct timespec time_a;
    struct timespec time_b;
    struct timespec timeout;
    pid_t child;
    int child_status;
    int sync_pipe[2];
    int rights_pipe[2];
    int received_fd;
    int listener;
    int duplicate_listener;
    int unix_client;
    int accepted;
    int epoll_fd;
    int missing_client;
    int lifetime_fd;
    int shared_fd;
    int shared_readonly_fd;
    int vectored_fd;
    int vectored_readonly_fd;
    int vectored_writeonly_fd;
    int vectored_pipe[2];
    int offset_fd;
    int *fillers;
    size_t filler_count;
    ssize_t vectored_result;
    char signal_byte;
    char socket_buffer[8] = {0};
    char vector_buffer[64] = {0};
    char vector_readback[64] = {0};
    char *pipe_payload;
    struct sockaddr_un unix_address;
    struct epoll_event epoll_event;
    struct sigaction signal_action;
    struct iovec socket_iov[2];
    struct iovec vectored_iov[2];
    struct iovec above_uio_max[1025] = {{0}};
    struct msghdr socket_message;
    struct cmsghdr *control_message;
    struct rlimit old_rlimit;
    struct rlimit new_rlimit;
    void *mapping;
    void *private_mapping;
    void *reservation_mapping;
    unsigned char *mapped_bytes;
    char path_buffer[PATH_MAX];
    char control_buffer[CMSG_SPACE(sizeof(int))];
    int pipe_fds[2];
    int socket_fds[2];
    int cwd_fd;
    int lock_fd;
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
    mode_fd = open("/tmp/jasper-file-mode", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, 0666);
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
    lock_fd = open("/tmp/jasper-record-lock", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (lock_fd < 0 || write(lock_fd, "lock", 4) != 4) return 42;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    lock.l_len = 4;
    if (fcntl(lock_fd, F_SETLK, &lock) != 0) return 43;
    child = fork();
    if (child == 0) {
        int child_fd = open("/tmp/jasper-record-lock", O_RDWR);
        struct flock probe;
        if (child_fd < 0) _exit(1);
        memset(&probe, 0, sizeof(probe));
        probe.l_type = F_WRLCK;
        probe.l_whence = SEEK_SET;
        probe.l_len = 4;
        if (fcntl(child_fd, F_GETLK, &probe) != 0 ||
            probe.l_type == F_UNLCK) _exit(2);
        errno = 0;
        if (fcntl(child_fd, F_SETLK, &probe) != -1 ||
            (errno != EACCES && errno != EAGAIN)) _exit(3);
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 44;
    if (pipe(sync_pipe) != 0) return 47;
    child = fork();
    if (child == 0) {
        int child_fd = open("/tmp/jasper-record-lock", O_RDWR);
        struct flock waiting;
        close(sync_pipe[0]);
        if (child_fd < 0) _exit(1);
        memset(&waiting, 0, sizeof(waiting));
        waiting.l_type = F_WRLCK;
        waiting.l_whence = SEEK_SET;
        waiting.l_len = 4;
        if (write(sync_pipe[1], "R", 1) != 1) _exit(2);
        if (fcntl(child_fd, F_SETLKW, &waiting) != 0) _exit(3);
        _exit(0);
    }
    close(sync_pipe[1]);
    if (child < 0 || read(sync_pipe[0], &signal_byte, 1) != 1) return 48;
    usleep(100000);
    lock.l_type = F_UNLCK;
    if (fcntl(lock_fd, F_SETLK, &lock) != 0) return 49;
    if (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 50;
    close(sync_pipe[0]);
    lock.l_type = F_WRLCK;
    if (fcntl(lock_fd, F_SETLK, &lock) != 0) return 51;
    if (pipe(sync_pipe) != 0) return 52;
    child = fork();
    if (child == 0) {
        int child_fd = open("/tmp/jasper-record-lock", O_RDWR);
        struct flock waiting;
        struct sigaction action;
        close(sync_pipe[0]);
        if (child_fd < 0) _exit(1);
        memset(&action, 0, sizeof(action));
        action.sa_handler = handle_signal;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, NULL) != 0) _exit(2);
        memset(&waiting, 0, sizeof(waiting));
        waiting.l_type = F_WRLCK;
        waiting.l_whence = SEEK_SET;
        waiting.l_len = 4;
        if (write(sync_pipe[1], "R", 1) != 1) _exit(3);
        errno = 0;
        if (fcntl(child_fd, F_SETLKW, &waiting) != -1 ||
            errno != EINTR || !interrupted) _exit(4);
        _exit(0);
    }
    close(sync_pipe[1]);
    if (child < 0 || read(sync_pipe[0], &signal_byte, 1) != 1) return 53;
    if (kill(child, SIGUSR1) != 0 ||
        waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 54;
    close(sync_pipe[0]);
    lock.l_type = F_UNLCK;
    if (fcntl(lock_fd, F_SETLK, &lock) != 0 || close(lock_fd) != 0) return 45;
    mode_fd = open("/tmp/jasper-record-lock", O_RDONLY);
    if (mode_fd < 0) return 55;
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_len = 4;
    errno = 0;
    if (fcntl(mode_fd, F_SETLK, &lock) != -1 || errno != EBADF) return 56;
    close(mode_fd);
    if (clock_gettime(CLOCK_MONOTONIC, &time_a) != 0) return 57;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 20000000;
    if (nanosleep(&timeout, NULL) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &time_b) != 0 ||
        time_b.tv_sec < time_a.tv_sec ||
        (time_b.tv_sec == time_a.tv_sec && time_b.tv_nsec < time_a.tv_nsec)) {
        return 58;
    }
    timeout = time_b;
    timeout.tv_nsec += 20000000;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_nsec -= 1000000000;
        timeout.tv_sec++;
    }
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &timeout, NULL) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &time_b) != 0 ||
        time_b.tv_sec < timeout.tv_sec ||
        (time_b.tv_sec == timeout.tv_sec && time_b.tv_nsec < timeout.tv_nsec)) {
        return 59;
    }
    errno = 0;
    if (clock_gettime((clockid_t)-1, &time_b) != -1 || errno != EINVAL) return 60;
    timeout.tv_sec = 0;
    timeout.tv_nsec = -1;
    errno = 0;
    if (nanosleep(&timeout, NULL) != -1 || errno != EINVAL) return 61;
    unlink("/tmp/jasper-unix.sock");
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return 62;
    memset(&unix_address, 0, sizeof(unix_address));
    unix_address.sun_family = AF_UNIX;
    strcpy(unix_address.sun_path, "/tmp/jasper-unix.sock");
    if (bind(listener, (struct sockaddr *)&unix_address, sizeof(unix_address)) != 0 ||
        listen(listener, 1) != 0) return 63;
    if (fstat(listener, &st) != 0 || !S_ISSOCK(st.st_mode)) return 64;
    duplicate_listener = socket(AF_UNIX, SOCK_STREAM, 0);
    errno = 0;
    if (duplicate_listener < 0 ||
        bind(duplicate_listener, (struct sockaddr *)&unix_address,
             sizeof(unix_address)) != -1 ||
        errno != EADDRINUSE) return 65;
    close(duplicate_listener);
    missing_client = socket(AF_UNIX, SOCK_STREAM, 0);
    unix_address.sun_path[strlen("/tmp/jasper-unix.sock")] = 'x';
    errno = 0;
    if (missing_client < 0 ||
        connect(missing_client, (struct sockaddr *)&unix_address,
                sizeof(unix_address)) != -1 ||
        errno != ENOENT) return 66;
    close(missing_client);
    unix_address.sun_path[strlen("/tmp/jasper-unix.sock")] = '\0';
    unix_client = socket(AF_UNIX, SOCK_STREAM, 0);
    epoll_fd = epoll_create1(0);
    if (unix_client < 0 || epoll_fd < 0 ||
        connect(unix_client, (struct sockaddr *)&unix_address,
                sizeof(unix_address)) != 0) return 67;
    memset(&epoll_event, 0, sizeof(epoll_event));
    epoll_event.events = EPOLLIN | EPOLLET;
    epoll_event.data.fd = listener;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listener, &epoll_event) != 0 ||
        epoll_wait(epoll_fd, &epoll_event, 1, 1000) != 1) return 68;
    accepted = accept(listener, NULL, NULL);
    if (accepted < 0) return 69;
    if (send(accepted, "hello", 5, 0) != 5 ||
        recv(unix_client, socket_buffer, 5, 0) != 5 ||
        memcmp(socket_buffer, "hello", 5) != 0) return 70;
    if (pipe(rights_pipe) != 0) return 71;
    memset(control_buffer, 0, sizeof(control_buffer));
    memset(&socket_message, 0, sizeof(socket_message));
    socket_iov[0].iov_base = "AB";
    socket_iov[0].iov_len = 2;
    socket_iov[1].iov_base = "CD";
    socket_iov[1].iov_len = 2;
    socket_message.msg_iov = socket_iov;
    socket_message.msg_iovlen = 2;
    socket_message.msg_control = control_buffer;
    socket_message.msg_controllen = sizeof(control_buffer);
    control_message = CMSG_FIRSTHDR(&socket_message);
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(control_message), &rights_pipe[0], sizeof(int));
    if (sendmsg(unix_client, &socket_message, 0) != 4) return 72;
    memset(socket_buffer, 0, sizeof(socket_buffer));
    memset(control_buffer, 0, sizeof(control_buffer));
    memset(&socket_message, 0, sizeof(socket_message));
    socket_message.msg_iov = socket_iov;
    socket_iov[0].iov_base = socket_buffer;
    socket_iov[0].iov_len = sizeof(socket_buffer);
    socket_message.msg_iovlen = 1;
    socket_message.msg_control = control_buffer;
    socket_message.msg_controllen = sizeof(control_buffer);
    if (recvmsg(accepted, &socket_message, 0) != 4 ||
        memcmp(socket_buffer, "ABCD", 4) != 0) return 73;
    control_message = CMSG_FIRSTHDR(&socket_message);
    if (!control_message || control_message->cmsg_level != SOL_SOCKET ||
        control_message->cmsg_type != SCM_RIGHTS ||
        control_message->cmsg_len < CMSG_LEN(sizeof(int))) return 74;
    memcpy(&received_fd, CMSG_DATA(control_message), sizeof(int));
    close(rights_pipe[0]);
    if (write(rights_pipe[1], "R", 1) != 1 ||
        read(received_fd, socket_buffer, 1) != 1 ||
        socket_buffer[0] != 'R') return 75;
    close(received_fd);
    close(rights_pipe[1]);
    memset(control_buffer, 0, sizeof(control_buffer));
    memset(&socket_message, 0, sizeof(socket_message));
    socket_iov[0].iov_base = "X";
    socket_iov[0].iov_len = 1;
    socket_message.msg_iov = socket_iov;
    socket_message.msg_iovlen = 1;
    socket_message.msg_control = control_buffer;
    socket_message.msg_controllen = sizeof(control_buffer);
    control_message = CMSG_FIRSTHDR(&socket_message);
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = 0;
    errno = 0;
    if (sendmsg(unix_client, &socket_message, 0) != -1 || errno != EINVAL) return 81;
    socket_message.msg_control = NULL;
    socket_message.msg_controllen = 0;
    socket_iov[0].iov_base = (void *)1;
    socket_iov[0].iov_len = 1;
    errno = 0;
    if (sendmsg(unix_client, &socket_message, 0) != -1 || errno != EFAULT) return 82;
    socket_iov[0].iov_base = "EF";
    socket_iov[0].iov_len = 2;
    socket_iov[1].iov_base = "GH";
    socket_iov[1].iov_len = 2;
    if (writev(accepted, socket_iov, 2) != 4) return 76;
    memset(socket_buffer, 0, sizeof(socket_buffer));
    socket_iov[0].iov_base = socket_buffer;
    socket_iov[0].iov_len = 2;
    socket_iov[1].iov_base = socket_buffer + 2;
    socket_iov[1].iov_len = 2;
    if (readv(unix_client, socket_iov, 2) != 4 ||
        memcmp(socket_buffer, "EFGH", 4) != 0) return 77;
    if (pipe(rights_pipe) != 0 || getrlimit(RLIMIT_NOFILE, &old_rlimit) != 0) {
        return 93;
    }
    new_rlimit = old_rlimit;
    new_rlimit.rlim_cur = 16;
    if (setrlimit(RLIMIT_NOFILE, &new_rlimit) != 0) return 94;
    if (getrlimit(RLIMIT_NOFILE, &new_rlimit) != 0 ||
        new_rlimit.rlim_cur != 16) return 98;
    fillers = calloc(64, sizeof(int));
    if (!fillers) return 99;
    filler_count = 0;
    errno = 0;
    while (filler_count < 64) {
        int filler_fd = dup(STDIN_FILENO);
        if (filler_fd < 0) break;
        fillers[filler_count++] = filler_fd;
    }
    if (errno != EMFILE) return 100;
    memset(control_buffer, 0, sizeof(control_buffer));
    memset(&socket_message, 0, sizeof(socket_message));
    socket_iov[0].iov_base = "Q";
    socket_iov[0].iov_len = 1;
    socket_message.msg_iov = socket_iov;
    socket_message.msg_iovlen = 1;
    socket_message.msg_control = control_buffer;
    socket_message.msg_controllen = sizeof(control_buffer);
    control_message = CMSG_FIRSTHDR(&socket_message);
    control_message->cmsg_level = SOL_SOCKET;
    control_message->cmsg_type = SCM_RIGHTS;
    control_message->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(control_message), &rights_pipe[0], sizeof(int));
    if (sendmsg(unix_client, &socket_message, 0) != 1) return 95;
    memset(control_buffer, 0, sizeof(control_buffer));
    memset(&socket_message, 0, sizeof(socket_message));
    socket_iov[0].iov_base = socket_buffer;
    socket_iov[0].iov_len = 1;
    socket_message.msg_iov = socket_iov;
    socket_message.msg_iovlen = 1;
    socket_message.msg_control = control_buffer;
    socket_message.msg_controllen = sizeof(control_buffer);
    errno = 0;
    if (recvmsg(accepted, &socket_message, 0) != 1 ||
        (socket_message.msg_flags & MSG_CTRUNC) == 0 ||
        socket_message.msg_controllen != 0) return 96;
    while (filler_count > 0) close(fillers[--filler_count]);
    free(fillers);
    close(rights_pipe[0]);
    close(rights_pipe[1]);
    if (setrlimit(RLIMIT_NOFILE, &old_rlimit) != 0) return 97;
    vectored_fd = open("/tmp/jasper-vectored",
                       O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (vectored_fd < 0 || ftruncate(vectored_fd, 64) != 0) return 140;
    memcpy(vector_buffer, "abcdef", 6);
    vectored_iov[0].iov_base = vector_buffer;
    vectored_iov[0].iov_len = 3;
    vectored_iov[1].iov_base = vector_buffer + 3;
    vectored_iov[1].iov_len = 3;
    if (writev(vectored_fd, vectored_iov, 2) != 6) return 141;
    if (lseek(vectored_fd, 0, SEEK_SET) != 0) return 142;
    vectored_iov[0].iov_base = vector_readback;
    vectored_iov[0].iov_len = 2;
    vectored_iov[1].iov_base = vector_readback + 2;
    vectored_iov[1].iov_len = 4;
    if (readv(vectored_fd, vectored_iov, 2) != 6 ||
        memcmp(vector_readback, "abcdef", 6) != 0 ||
        lseek(vectored_fd, 0, SEEK_CUR) != 6) return 143;
    if (lseek(vectored_fd, 5, SEEK_SET) != 5) return 144;
    memset(vector_readback, 0, sizeof(vector_readback));
    if (preadv(vectored_fd, vectored_iov, 2, 0) != 6 ||
        memcmp(vector_readback, "abcdef", 6) != 0 ||
        lseek(vectored_fd, 0, SEEK_CUR) != 5) return 145;
    memcpy(vector_buffer + 32, "ghijkl", 6);
    vectored_iov[0].iov_base = vector_buffer + 32;
    vectored_iov[0].iov_len = 2;
    vectored_iov[1].iov_base = vector_buffer + 34;
    vectored_iov[1].iov_len = 4;
    if (pwritev(vectored_fd, vectored_iov, 2, 32) != 6 ||
        pread(vectored_fd, vector_readback, 6, 32) != 6 ||
        memcmp(vector_readback, "ghijkl", 6) != 0 ||
        lseek(vectored_fd, 0, SEEK_CUR) != 5) return 146;
    vectored_readonly_fd = open("/tmp/jasper-vectored", O_RDONLY);
    vectored_writeonly_fd = open("/tmp/jasper-vectored", O_WRONLY);
    vectored_iov[0].iov_base = vector_buffer;
    vectored_iov[0].iov_len = 1;
    vectored_iov[1].iov_len = 0;
    errno = 0;
    if (vectored_readonly_fd < 0 || vectored_writeonly_fd < 0 ||
        pwritev(vectored_readonly_fd, vectored_iov, 1, 0) != -1 ||
        errno != EBADF) return 147;
    errno = 0;
    if (readv(vectored_writeonly_fd, vectored_iov, 1) != -1 ||
        errno != EBADF) return 148;
    errno = 0;
    if (readv(vectored_fd, (struct iovec *)1, 1) != -1 ||
        errno != EFAULT || lseek(vectored_fd, 0, SEEK_CUR) != 5) return 149;
    errno = 0;
    if (writev(vectored_fd, (struct iovec *)1, 1) != -1 ||
        errno != EFAULT || lseek(vectored_fd, 0, SEEK_CUR) != 5) return 155;
    errno = 0;
    if (readv(vectored_fd, above_uio_max, 1025) != -1 ||
        errno != EINVAL) return 150;
    if (pipe(vectored_pipe) != 0 ||
        fcntl(vectored_pipe[1], F_SETPIPE_SZ, 4096) != 4096 ||
        fcntl(vectored_pipe[1], F_SETFL, O_NONBLOCK) != 0) return 151;
    pipe_payload = malloc(8192);
    if (!pipe_payload) return 152;
    memset(pipe_payload, 'v', 8192);
    vectored_iov[0].iov_base = pipe_payload;
    vectored_iov[0].iov_len = 4096;
    vectored_iov[1].iov_base = pipe_payload + 4096;
    vectored_iov[1].iov_len = 4096;
    vectored_result = writev(vectored_pipe[1], vectored_iov, 2);
    if (vectored_result <= 0 || vectored_result >= 8192) return 153;
    free(pipe_payload);
    close(vectored_pipe[0]);
    close(vectored_pipe[1]);
    close(vectored_writeonly_fd);
    close(vectored_readonly_fd);
    close(vectored_fd);
    if (unlink("/tmp/jasper-vectored") != 0) return 154;
    mode_fd = open("/tmp/jasper-rename-source", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (mode_fd < 0 || write(mode_fd, "new", 3) != 3) return 165;
    close(mode_fd);
    mode_fd = open("/tmp/jasper-rename-target", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (mode_fd < 0 || write(mode_fd, "old", 3) != 3) return 166;
    close(mode_fd);
    if (rename("/tmp/jasper-rename-source", "/tmp/jasper-rename-target") != 0)
        return 167;
    errno = 0;
    if (open("/tmp/jasper-rename-source", O_RDONLY) != -1 ||
        errno != ENOENT) return 168;
    mode_fd = open("/tmp/jasper-rename-target", O_RDONLY);
    if (mode_fd < 0 || read(mode_fd, path_buffer, 3) != 3 ||
        memcmp(path_buffer, "new", 3) != 0) return 169;
    close(mode_fd);
    if (unlink("/tmp/jasper-rename-target") != 0) return 170;
    if (mkdir("/tmp/jasper-vfs", 0700) != 0 ||
        mkdir("/tmp/jasper-vfs/a", 0700) != 0 ||
        mkdir("/tmp/jasper-vfs/a/b", 0700) != 0) return 101;
    mode_fd = open("/tmp/jasper-vfs/a/b/file", O_CREAT | O_RDWR, 0600);
    if (mode_fd < 0 || write(mode_fd, "path", 4) != 4) return 102;
    close(mode_fd);
    unlink("/tmp/jasper-vfs/link");
    if (symlink("a", "/tmp/jasper-vfs/link") != 0) return 130;
    if (readlink("/tmp/jasper-vfs/link", path_buffer,
                 sizeof(path_buffer)) != 1) return 131;
    if (path_buffer[0] != 'a') return 132;
    mode_fd = open("/tmp/jasper-vfs//link/./b/../b/file", O_RDONLY);
    if (mode_fd < 0) return 133;
    if (read(mode_fd, path_buffer, 4) != 4) return 134;
    if (memcmp(path_buffer, "path", 4) != 0) return 135;
    close(mode_fd);
    if (!realpath("/tmp/jasper-vfs/link/b/file", path_buffer) ||
        strcmp(path_buffer, "/tmp/jasper-vfs/a/b/file") != 0) return 136;
    errno = 0;
    if (readlink("/tmp/jasper-vfs/a/b/file", path_buffer,
                 sizeof(path_buffer)) != -1 || errno != EINVAL) return 137;
    errno = 0;
    if (open("/tmp/../../jasper-missing", O_RDONLY) != -1 ||
        errno != ENOENT) return 107;
    lifetime_fd = open("/tmp/jasper-unlink-life", O_CREAT | O_RDWR, 0600);
    if (lifetime_fd < 0 || write(lifetime_fd, "life", 4) != 4 ||
        unlink("/tmp/jasper-unlink-life") != 0) return 108;
    errno = 0;
    if (open("/tmp/jasper-unlink-life", O_RDONLY) != -1 ||
        errno != ENOENT || pread(lifetime_fd, path_buffer, 4, 0) != 4 ||
        memcmp(path_buffer, "life", 4) != 0) return 109;
    mapping = mmap(NULL, 4096, PROT_READ, MAP_SHARED, lifetime_fd, 0);
    if (mapping == MAP_FAILED || memcmp(mapping, "life", 4) != 0) return 110;
    munmap(mapping, 4096);
    close(lifetime_fd);
    shared_fd = open("/tmp/jasper-shared", O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (shared_fd < 0 || ftruncate(shared_fd, 4096) != 0) return 111;
    mapped_bytes = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                        MAP_SHARED, shared_fd, 0);
    if (mapped_bytes == MAP_FAILED) return 112;
    mapped_bytes[0] = 'A';
    if (pread(shared_fd, path_buffer, 1, 0) != 1 || path_buffer[0] != 'A') {
        return 113;
    }
    child = fork();
    if (child == 0) {
        unsigned char *child_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                        MAP_SHARED, shared_fd, 0);
        if (child_map == MAP_FAILED || child_map[0] != 'A') _exit(1);
        child_map[0] = 'C';
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        mapped_bytes[0] != 'C') return 114;
    mapped_bytes[0] = 'B';
    child = fork();
    if (child == 0) {
        unsigned char *child_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE, shared_fd, 0);
        if (child_map == MAP_FAILED || child_map[0] != 'B') _exit(1);
        child_map[0] = 'D';
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        mapped_bytes[0] != 'B') return 115;
    shared_readonly_fd = open("/tmp/jasper-shared", O_RDONLY);
    errno = 0;
    if (shared_readonly_fd < 0 ||
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
             shared_readonly_fd, 0) != MAP_FAILED ||
        errno != EACCES) return 116;
    if (unlink("/tmp/jasper-shared") != 0) return 117;
    errno = 0;
    if (open("/tmp/jasper-shared", O_RDONLY) != -1 ||
        errno != ENOENT || mapped_bytes[0] != 'B') return 118;
    munmap(mapped_bytes, 4096);
    close(shared_readonly_fd);
    close(shared_fd);
    mapping = mmap((void *)0x100000000ULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    private_mapping = mmap((void *)0x140000000ULL, 4096, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapping == MAP_FAILED || private_mapping == MAP_FAILED) return 119;
    ((unsigned char *)mapping)[0] = 1;
    ((unsigned char *)private_mapping)[0] = 2;
    munmap(mapping, 4096);
    munmap(private_mapping, 4096);
    errno = 0;
    if (mmap((void *)0x100000ULL, 4096, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0)
            != MAP_FAILED || errno != ENOMEM) return 120;
    errno = 0;
    if (mmap((void *)0x8000000000ULL, 4096, PROT_READ,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0)
            != MAP_FAILED || errno != ENOMEM) return 121;
    mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    if (mapping == MAP_FAILED || (uintptr_t)mapping >= 0x80000000ULL) return 122;
    munmap(mapping, 4096);
    offset_fd = open("/tmp/jasper-offset-shared",
                     O_CREAT | O_TRUNC | O_RDWR, 0600);
    if (offset_fd < 0 || ftruncate(offset_fd, 8192) != 0 ||
        pwrite(offset_fd, "H", 1, 4096) != 1) return 156;
    mapping = mmap((void *)0x160000000ULL, 4096,
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED_NOREPLACE, offset_fd, 4096);
    if (mapping == MAP_FAILED || ((char *)mapping)[0] != 'H') return 157;
    ((char *)mapping)[0] = 'I';
    if (pread(offset_fd, path_buffer, 1, 4096) != 1 ||
        path_buffer[0] != 'I') return 158;
    private_mapping = mmap((void *)0x160000000ULL, 4096,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (private_mapping != (void *)0x160000000ULL) return 159;
    ((char *)private_mapping)[0] = 'R';
    munmap(private_mapping, 4096);
    mapping = mmap((void *)0x170000000ULL, 8192,
                   PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_FIXED_NOREPLACE, offset_fd, 0);
    if (mapping == MAP_FAILED) return 162;
    if (ftruncate(offset_fd, 4096) != 0 ||
        fstat(offset_fd, &st) != 0 || st.st_size != 4096 ||
        pread(offset_fd, path_buffer, 1, 4096) != 0) return 160;
    child = fork();
    if (child == 0) {
        volatile char truncated = ((volatile char *)mapping)[4096];
        (void)truncated;
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFSIGNALED(child_status) || WTERMSIG(child_status) != SIGBUS) return 163;
    munmap(mapping, 8192);
    mapping = mmap((void *)0x170000000ULL, 4096,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapping == MAP_FAILED) return 164;
    ((char *)mapping)[0] = 'T';
    munmap(mapping, 4096);
    close(offset_fd);
    if (unlink("/tmp/jasper-offset-shared") != 0) return 161;
    reservation_mapping = mmap(NULL, 8192, PROT_NONE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reservation_mapping == MAP_FAILED) return 165;
    if (mprotect(reservation_mapping, 8192,
                 PROT_READ | PROT_WRITE) != 0) return 166;
    ((char *)reservation_mapping)[0] = 'P';
    child = fork();
    if (child == 0) {
        if (((volatile char *)reservation_mapping)[0] != 'P') _exit(1);
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 167;
    munmap(reservation_mapping, 8192);
    if (epoll_wait(epoll_fd, &epoll_event, 1, 0) != 0) return 83;
    memset(&epoll_event, 0, sizeof(epoll_event));
    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = 99;
    errno = 0;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, 99, &epoll_event) != -1 ||
        errno != EBADF) return 84;
    memset(&epoll_event, 0, sizeof(epoll_event));
    epoll_event.events = EPOLLIN;
    epoll_event.data.fd = accepted;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, accepted, &epoll_event) != 0) return 85;
    if (send(unix_client, "Z", 1, 0) != 1 ||
        epoll_wait(epoll_fd, &epoll_event, 1, 1000) != 1 ||
        recv(accepted, socket_buffer, 1, 0) != 1 ||
        socket_buffer[0] != 'Z') return 86;
    memset(&signal_action, 0, sizeof(signal_action));
    signal_action.sa_handler = handle_signal;
    sigemptyset(&signal_action.sa_mask);
    if (sigaction(SIGUSR1, &signal_action, NULL) != 0) return 90;
    interrupted = 0;
    memset(&child_status, 0, sizeof(child_status));
    child = fork();
    if (child == 0) {
        usleep(20000);
        if (kill(getppid(), SIGUSR1) != 0) _exit(1);
        _exit(0);
    }
    if (child < 0) return 87;
    errno = 0;
    if (epoll_wait(epoll_fd, &epoll_event, 1, 1000) != -1 ||
        errno != EINTR || !interrupted) return 88;
    if (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 89;
    if (clock_gettime(CLOCK_MONOTONIC, &time_a) != 0 ||
        epoll_wait(epoll_fd, &epoll_event, 1, 20) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &time_b) != 0) return 91;
    if (time_b.tv_sec == time_a.tv_sec &&
        time_b.tv_nsec - time_a.tv_nsec < 10000000) return 92;
    if (unlink("/tmp/jasper-unix.sock") != 0) return 78;
    unix_address.sun_path[strlen("/tmp/jasper-unix.sock")] = 'x';
    missing_client = socket(AF_UNIX, SOCK_STREAM, 0);
    errno = 0;
    if (missing_client < 0 ||
        connect(missing_client, (struct sockaddr *)&unix_address,
                sizeof(unix_address)) != -1 ||
        errno != ENOENT) return 79;
    close(missing_client);
    close(unix_client);
    if (recv(accepted, socket_buffer, 1, 0) != 0) return 80;
    close(accepted);
    close(listener);
    close(epoll_fd);
    child = fork();
    if (child == 0) {
        int child_fd = open("/tmp/jasper-record-lock", O_RDWR);
        struct flock acquired;
        if (child_fd < 0) _exit(1);
        memset(&acquired, 0, sizeof(acquired));
        acquired.l_type = F_WRLCK;
        acquired.l_whence = SEEK_SET;
        acquired.l_len = 4;
        if (fcntl(child_fd, F_SETLK, &acquired) != 0) _exit(2);
        _exit(0);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) return 46;
    close(pipe_fds[0]);
    close(pipe_fds[1]);
    close(socket_fds[0]);
    close(socket_fds[1]);
    if (fd < 0) return 10;
    file = fdopen(fd, "w");
    if (!file) return 11;
    if (fputs("fdopen-ok\n", file) < 0) return 12;
    if (fclose(file) != 0) return 13;
    if (unlink("/tmp/jasper-vfs/a/b/file") != 0 ||
        unlink("/tmp/jasper-vfs/link") != 0 ||
        rmdir("/tmp/jasper-vfs/a/b") != 0 ||
        rmdir("/tmp/jasper-vfs/a") != 0 ||
        rmdir("/tmp/jasper-vfs") != 0) return 14;
    puts("FILE_STDIO_OK stdio_stat=true pipe_stat=true socket_stat=true file_status=true positioned_io=true vectored_fd=true cwd_status=true record_lock=true monotonic_time=true unix_socket=true socket_message=true epoll_status=true vfs_path=true unlink_lifetime=true shared_mmap=true materialized_fork_inherit=true low_window=true");
    return 0;
}
