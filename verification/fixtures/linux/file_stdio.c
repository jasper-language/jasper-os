#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
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
    int *fillers;
    size_t filler_count;
    char signal_byte;
    char socket_buffer[8] = {0};
    struct sockaddr_un unix_address;
    struct epoll_event epoll_event;
    struct sigaction signal_action;
    struct iovec socket_iov[2];
    struct msghdr socket_message;
    struct cmsghdr *control_message;
    struct rlimit old_rlimit;
    struct rlimit new_rlimit;
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
    puts("FILE_STDIO_OK stdio_stat=true pipe_stat=true socket_stat=true file_status=true positioned_io=true cwd_status=true record_lock=true monotonic_time=true unix_socket=true socket_message=true epoll_status=true");
    return 0;
}
