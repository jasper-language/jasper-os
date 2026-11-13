// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/android/binder.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <linux/sync_file.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <utime.h>
#include <unistd.h>

#define JASPER_ASHMEM_SET_NAME 0x41006101UL
#define JASPER_ASHMEM_SET_PROT_MASK 0x40046102UL
#define JASPER_ASHMEM_SET_SIZE 0x40086103UL
#define JASPER_ASHMEM_GET_SIZE 0x80086104UL
#define JASPER_ASHMEM_PIN 0x40086105UL
#define JASPER_ASHMEM_UNPIN 0x40086106UL
#define JASPER_ASHMEM_GET_NAME 0x81006107UL
#define JASPER_ASHMEM_GET_PROT_MASK 0x80086108UL
#define JASPER_ASHMEM_GET_PIN_STATUS 0x6109UL
#define JASPER_ION_IOC_ALLOC 0xc0204900UL
#define JASPER_ION_IOC_FREE 0xc0044901UL
#define JASPER_ION_IOC_MAP 0xc0084902UL
#define JASPER_ION_IOC_SHARE 0xc0084904UL
#define JASPER_ION_IOC_IMPORT 0xc0084905UL
#define JASPER_ION_IOC_SYNC 0xc0084907UL
#define JASPER_ION_HEAP_SYSTEM_MASK 1U

struct jasper_ion_allocation_data {
    size_t len;
    size_t align;
    unsigned int heap_id_mask;
    unsigned int flags;
    int handle;
};

struct jasper_ion_fd_data {
    int handle;
    int fd;
};

struct jasper_ion_handle_data {
    int handle;
};

static void signal_noop(int signal) {
    (void)signal;
}

static uint32_t futex_word;
static atomic_int futex_started;
static atomic_int futex_finished;

struct futex_thread_arg {
    uint32_t bitset;
};

static void *futex_waiter(void *argument) {
    struct futex_thread_arg *arg = argument;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        return (void *)(intptr_t)-1000;
    }
    deadline.tv_sec += 1;
    atomic_fetch_add_explicit(&futex_started, 1, memory_order_release);
    long result = syscall(SYS_futex, &futex_word,
                          FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG, 0,
                          &deadline, NULL, arg->bitset);
    atomic_fetch_add_explicit(&futex_finished, 1, memory_order_release);
    return (void *)(intptr_t)result;
}

int main(void) {
    if (getenv("JASPER_EXEC_CHILD") != NULL) {
        printf("jasper-exec-child pid=%d ppid=%d\n", getpid(), getppid());
        fflush(stdout);
        char *registry_argv[] = {"/usr/bin/printf", "jasper-registry-ok\n", NULL};
        char *registry_envp[] = {NULL};
        execve(registry_argv[0], registry_argv, registry_envp);
        printf("jasper-registry-fail errno=%d\n", errno);
        return 74;
    }
    pid_t parent = getppid();
    if (parent != 0) {
        return 2;
    }
    sigset_t blocked_signal;
    sigset_t pending_signal;
    sigemptyset(&blocked_signal);
    sigaddset(&blocked_signal, SIGUSR1);
    if (signal(SIGUSR1, signal_noop) == SIG_ERR ||
        sigprocmask(SIG_BLOCK, &blocked_signal, NULL) != 0 ||
        raise(SIGUSR1) != 0 ||
        sigpending(&pending_signal) != 0 ||
        !sigismember(&pending_signal, SIGUSR1) ||
        sigprocmask(SIG_UNBLOCK, &blocked_signal, NULL) != 0) {
        return 238;
    }
    int fd = open("/usr/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return 3;
    }
    off_t end = lseek(fd, 0, SEEK_END);
    if (end < 4 || lseek(fd, 0, SEEK_SET) != 0) {
        return 4;
    }
    unsigned char magic[4];
    errno = 0;
    if (readv(fd, (struct iovec *)1, 1) != -1 || errno != EFAULT ||
        lseek(fd, 0, SEEK_CUR) != 0) {
        return 5;
    }
    struct iovec vectors[2] = {
        {.iov_base = magic, .iov_len = 2},
        {.iov_base = magic + 2, .iov_len = 2},
    };
    if (readv(fd, vectors, 2) != (ssize_t)sizeof(magic) ||
        magic[0] != 0x7f || magic[1] != 'E' || magic[2] != 'L' || magic[3] != 'F') {
        return 6;
    }
    errno = 0;
    if (readv(-1, vectors, 2) != -1 || errno != EBADF) {
        return 7;
    }
    struct iovec too_many[17] = {0};
    errno = 0;
    if (readv(fd, too_many, 17) != -1 || errno != EINVAL) {
        return 8;
    }
    if (lseek(fd, -4, SEEK_END) != end - 4 ||
        lseek(fd, 0, SEEK_CUR) != end - 4) {
        return 9;
    }
    errno = 0;
    if (lseek(STDOUT_FILENO, 0, SEEK_CUR) != -1 || errno != ESPIPE) {
        return 10;
    }
    if (lseek(fd, 4, SEEK_SET) != 4) {
        return 71;
    }
    int dup_fd = dup(fd);
    if (dup_fd < 0 || lseek(dup_fd, 0, SEEK_CUR) != 4 ||
        fcntl(dup_fd, F_GETFD) != 0) {
        return 72;
    }
    if (lseek(dup_fd, 8, SEEK_SET) != 8 ||
        lseek(fd, 0, SEEK_CUR) != 8 ||
        dup2(fd, fd) != fd ||
        (fcntl(fd, F_GETFD) & FD_CLOEXEC) == 0) {
        return 73;
    }
    int dup2_fd = dup2(fd, 20);
    if (dup2_fd != 20 || fcntl(20, F_GETFD) != 0 ||
        lseek(20, 0, SEEK_CUR) != 8) {
        return 74;
    }
    int dup3_fd = dup3(fd, 21, O_CLOEXEC);
    if (dup3_fd != 21 || fcntl(21, F_GETFD) != FD_CLOEXEC ||
        lseek(21, 0, SEEK_CUR) != 8) {
        return 75;
    }
    if (dup2(fd, 40) != 40 || dup2(fd, 41) != 41 ||
        syscall(SYS_close_range, 40, 41, 0) != 0) {
        return 225;
    }
    errno = 0;
    if (fcntl(40, F_GETFD) != -1 || errno != EBADF) {
        return 226;
    }
    if (dup2(fd, 42) != 42 ||
        syscall(SYS_close_range, 42, 42, 4) != 0 ||
        fcntl(42, F_GETFD) != FD_CLOEXEC || close(42) != 0) {
        return 227;
    }
    errno = 0;
    if (syscall(SYS_close_range, 50, 49, 0) != -1 || errno != EINVAL) {
        return 228;
    }
    if (dup2(fd, 43) != 43 ||
        syscall(SYS_close_range, 43, 43, 2) != 0) {
        return 229;
    }
    errno = 0;
    if (fcntl(43, F_GETFD) != -1 || errno != EBADF) {
        return 230;
    }
    errno = 0;
    if (syscall(SYS_close_range, 44, 44, 8) != -1 || errno != EINVAL) {
        return 231;
    }
    errno = 0;
    if (dup3(fd, fd, O_CLOEXEC) != -1 || errno != EINVAL) {
        return 76;
    }
    errno = 0;
    if (dup3(fd, 22, 0x40000000) != -1 || errno != EINVAL) {
        return 77;
    }
    errno = 0;
    if (dup3(63, 63, 0) != -1 || errno != EBADF) {
        return 80;
    }
    errno = 0;
    if (dup2(fd, 64) != -1 || errno != EBADF) {
        return 78;
    }
    if (close(dup_fd) != 0 || close(dup2_fd) != 0 || close(dup3_fd) != 0 ||
        lseek(fd, 0, SEEK_SET) != 0) {
        return 79;
    }
    int pipe_fds[2];
    int pipe_flags = O_CLOEXEC | O_NONBLOCK;
    if (pipe2(pipe_fds, pipe_flags) != 0) {
        printf("jasper-pipe2-fail stage=create flags=%#x errno=%d\n",
               pipe_flags, errno);
        return 86;
    }
    if (fsync(fd) != 0 || fdatasync(fd) != 0 || syncfs(fd) != 0) {
        return 199;
    }
    sync();
    errno = 0;
    if (fsync(pipe_fds[0]) != -1 || errno != EINVAL) {
        return 200;
    }
    int reader_flags = fcntl(pipe_fds[0], F_GETFL);
    int writer_flags = fcntl(pipe_fds[1], F_GETFL);
    if ((reader_flags & O_NONBLOCK) == 0 || (writer_flags & O_NONBLOCK) == 0) {
        printf("jasper-pipe2-fail stage=flags reader=%d writer=%d errno=%d\n",
               reader_flags, writer_flags, errno);
        return 86;
    }
    if (write(pipe_fds[1], "pipe", 4) != 4) {
        return 87;
    }
    char pipe_bytes[4];
    if (read(pipe_fds[0], pipe_bytes, sizeof(pipe_bytes)) != 4 ||
        memcmp(pipe_bytes, "pipe", 4) != 0) {
        return 88;
    }
    errno = 0;
    if (read(pipe_fds[0], pipe_bytes, sizeof(pipe_bytes)) != -1 ||
        errno != EAGAIN) {
        return 89;
    }
    if (close(pipe_fds[1]) != 0 ||
        read(pipe_fds[0], pipe_bytes, sizeof(pipe_bytes)) != 0) {
        return 90;
    }
    errno = 0;
    if (write(pipe_fds[1], "x", 1) != -1 || errno != EBADF) {
        return 91;
    }
    if (close(pipe_fds[0]) != 0) {
        return 92;
    }
    int blocking_pipe[2];
    if (pipe2(blocking_pipe, 0) != 0) {
        return 93;
    }
    pid_t pipe_child = fork();
    if (pipe_child < 0) {
        return 94;
    }
    if (pipe_child == 0) {
        _exit(write(blocking_pipe[1], "block", 5) == 5 ? 0 : 95);
    }
    char blocking_bytes[8] = {0};
    if (read(blocking_pipe[0], blocking_bytes, 5) != 5 ||
        memcmp(blocking_bytes, "block", 5) != 0) {
        return 96;
    }
    int pipe_status = 0;
    if (waitpid(pipe_child, &pipe_status, 0) != pipe_child ||
        !WIFEXITED(pipe_status) || WEXITSTATUS(pipe_status) != 0) {
        return 97;
    }
    if (close(blocking_pipe[0]) != 0 || close(blocking_pipe[1]) != 0) {
        return 98;
    }
    int event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    uint64_t event_value = 3;
    uint64_t event_read = 0;
    struct pollfd event_poll = {.fd = event_fd, .events = POLLIN};
    if (event_fd < 0 ||
        (fcntl(event_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        write(event_fd, &event_value, sizeof(event_value)) !=
            (ssize_t)sizeof(event_value) ||
        poll(&event_poll, 1, 0) != 1 ||
        (event_poll.revents & POLLIN) == 0 ||
        read(event_fd, &event_read, sizeof(event_read)) !=
            (ssize_t)sizeof(event_read) ||
        event_read != 3) {
        return 236;
    }
    errno = 0;
    if (read(event_fd, &event_read, sizeof(event_read)) != -1 ||
        errno != EAGAIN || close(event_fd) != 0) {
        return 237;
    }
    int broken_pipe[2];
    if (pipe2(broken_pipe, O_NONBLOCK) != 0 ||
        signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
        close(broken_pipe[0]) != 0) {
        return 99;
    }
    errno = 0;
    if (write(broken_pipe[1], "x", 1) != -1 || errno != EPIPE ||
        close(broken_pipe[1]) != 0) {
        return 100;
    }
    int socket_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                   0, socket_fds) != 0 ||
        (fcntl(socket_fds[0], F_GETFL) & O_NONBLOCK) == 0 ||
        (fcntl(socket_fds[1], F_GETFL) & O_NONBLOCK) == 0) {
        return 101;
    }
    if (write(socket_fds[0], "a2b", 3) != 3 ||
        read(socket_fds[1], blocking_bytes, 3) != 3 ||
        memcmp(blocking_bytes, "a2b", 3) != 0 ||
        write(socket_fds[1], "b2a", 3) != 3 ||
        read(socket_fds[0], blocking_bytes, 3) != 3 ||
        memcmp(blocking_bytes, "b2a", 3) != 0) {
        return 102;
    }
    struct sockaddr_un socket_name;
    socklen_t socket_name_len = sizeof(socket_name);
    if (getsockname(socket_fds[0], (struct sockaddr *)&socket_name,
                    &socket_name_len) != 0 ||
        socket_name_len < sizeof(sa_family_t) ||
        socket_name.sun_family != AF_UNIX ||
        getpeername(socket_fds[0], (struct sockaddr *)&socket_name,
                    &socket_name_len) != 0 ||
        socket_name.sun_family != AF_UNIX ||
        send(socket_fds[0], "send", 4, MSG_NOSIGNAL) != 4 ||
        recv(socket_fds[1], blocking_bytes, 4, 0) != 4 ||
        memcmp(blocking_bytes, "send", 4) != 0) {
        return 105;
    }
    if (shutdown(socket_fds[0], SHUT_WR) != 0 ||
        read(socket_fds[1], blocking_bytes, 1) != 0 ||
        write(socket_fds[1], "z", 1) != 1 ||
        read(socket_fds[0], blocking_bytes, 1) != 1 ||
        blocking_bytes[0] != 'z') {
        return 106;
    }
    if (close(socket_fds[1]) != 0 ||
        read(socket_fds[0], blocking_bytes, 1) != 0) {
        return 103;
    }
    errno = 0;
    if (write(socket_fds[0], "x", 1) != -1 || errno != EPIPE ||
        close(socket_fds[0]) != 0) {
        return 104;
    }
    static const char abstract_suffix[] = "jasper-abi-named";
    struct sockaddr_un named_address;
    memset(&named_address, 0, sizeof(named_address));
    named_address.sun_family = AF_UNIX;
    memcpy(&named_address.sun_path[1], abstract_suffix,
           sizeof(abstract_suffix));
    socklen_t named_length =
        offsetof(struct sockaddr_un, sun_path) + 1 + sizeof(abstract_suffix);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0 ||
        bind(listener, (struct sockaddr *)&named_address, named_length) != 0 ||
        listen(listener, 2) != 0) {
        return 107;
    }
    pid_t named_parent_pid = getpid();
    pid_t named_child = fork();
    if (named_child < 0) {
        return 108;
    }
    if (named_child == 0) {
        int client = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client < 0 ||
            connect(client, (struct sockaddr *)&named_address,
                    named_length) != 0) {
            _exit(134);
        }
        struct ucred peer_cred;
        socklen_t peer_cred_len = sizeof(peer_cred);
        int socket_type = 0;
        socklen_t socket_type_len = sizeof(socket_type);
        int passcred = 1;
        int passcred_result = 0;
        socklen_t passcred_result_len = sizeof(passcred_result);
        if (getsockopt(client, SOL_SOCKET, SO_PEERCRED, &peer_cred,
                       &peer_cred_len) != 0 ||
            peer_cred_len != sizeof(peer_cred) ||
            peer_cred.pid != named_parent_pid || peer_cred.uid != 0 ||
            peer_cred.gid != 0 ||
            getsockopt(client, SOL_SOCKET, SO_TYPE, &socket_type,
                       &socket_type_len) != 0 ||
            socket_type != SOCK_STREAM ||
            setsockopt(client, SOL_SOCKET, SO_PASSCRED, &passcred,
                       sizeof(passcred)) != 0 ||
            getsockopt(client, SOL_SOCKET, SO_PASSCRED, &passcred_result,
                       &passcred_result_len) != 0 ||
            passcred_result != 1) {
            _exit(135);
        }
        if (
            send(client, "hello", 5, MSG_NOSIGNAL) != 5 ||
            recv(client, blocking_bytes, 5, 0) != 5 ||
            memcmp(blocking_bytes, "world", 5) != 0) {
            _exit(109);
        }
        socklen_t local_length = sizeof(named_address);
        if (getsockname(client, (struct sockaddr *)&named_address,
                        &local_length) != 0 ||
            local_length != sizeof(sa_family_t)) {
            _exit(110);
        }
        socklen_t peer_length = sizeof(named_address);
        if (getpeername(client, (struct sockaddr *)&named_address,
                        &peer_length) != 0 ||
            peer_length != named_length ||
            memcmp(&named_address.sun_path[1], abstract_suffix,
                   sizeof(abstract_suffix)) != 0) {
            _exit(111);
        }
        close(client);
        close(listener);
        _exit(0);
    }
    struct sockaddr_un peer_address;
    socklen_t peer_length = sizeof(peer_address);
    int accepted = accept4(listener, (struct sockaddr *)&peer_address,
                           &peer_length, SOCK_CLOEXEC);
    if (accepted < 0 ||
        (fcntl(accepted, F_GETFD) & FD_CLOEXEC) == 0 ||
        peer_length != sizeof(sa_family_t) ||
        recv(accepted, blocking_bytes, 5, 0) != 5 ||
        memcmp(blocking_bytes, "hello", 5) != 0 ||
        send(accepted, "world", 5, MSG_NOSIGNAL) != 5) {
        return 112;
    }
    struct ucred accepted_peer_cred;
    socklen_t accepted_peer_cred_len = sizeof(accepted_peer_cred);
    if (
        getsockopt(accepted, SOL_SOCKET, SO_PEERCRED, &accepted_peer_cred,
                   &accepted_peer_cred_len) != 0 ||
        accepted_peer_cred_len != sizeof(accepted_peer_cred) ||
        accepted_peer_cred.pid != named_child ||
        accepted_peer_cred.uid != 0 || accepted_peer_cred.gid != 0) {
        return 136;
    }
    socklen_t accepted_name_length = sizeof(peer_address);
    if (getsockname(accepted, (struct sockaddr *)&peer_address,
                    &accepted_name_length) != 0 ||
        accepted_name_length != named_length ||
        memcmp(&peer_address.sun_path[1], abstract_suffix,
               sizeof(abstract_suffix)) != 0) {
        return 113;
    }
    int named_status = 0;
    if (waitpid(named_child, &named_status, 0) != named_child ||
        !WIFEXITED(named_status) || WEXITSTATUS(named_status) != 0 ||
        close(accepted) != 0 || close(listener) != 0) {
        return 114;
    }
    int rebound = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (rebound < 0 ||
        bind(rebound, (struct sockaddr *)&named_address, named_length) != 0 ||
        close(rebound) != 0) {
        return 115;
    }
    int message_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, message_fds) != 0) {
        return 116;
    }
    struct iovec send_vectors[2] = {
        {.iov_base = "mes", .iov_len = 3},
        {.iov_base = "sage", .iov_len = 4},
    };
    struct msghdr send_message = {
        .msg_iov = send_vectors,
        .msg_iovlen = 2,
    };
    if (sendmsg(message_fds[0], &send_message,
                MSG_NOSIGNAL | MSG_DONTWAIT) != 7) {
        return 117;
    }
    char message_first[4] = {0};
    char message_second[4] = {0};
    struct iovec receive_vectors[2] = {
        {.iov_base = message_first, .iov_len = 3},
        {.iov_base = message_second, .iov_len = 4},
    };
    struct msghdr receive_message = {
        .msg_iov = receive_vectors,
        .msg_iovlen = 2,
    };
    if (recvmsg(message_fds[1], &receive_message, 0) != 7 ||
        memcmp(message_first, "mes", 3) != 0 ||
        memcmp(message_second, "sage", 4) != 0 ||
        close(message_fds[0]) != 0 || close(message_fds[1]) != 0) {
        return 118;
    }
    int rights_fds[2];
    int transfer_pipe[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, rights_fds) != 0 ||
        pipe2(transfer_pipe, O_NONBLOCK) != 0) {
        return 119;
    }
    char rights_control[CMSG_SPACE(sizeof(int))];
    memset(rights_control, 0, sizeof(rights_control));
    char rights_byte = 'R';
    struct iovec rights_send_iov = {.iov_base = &rights_byte, .iov_len = 1};
    struct msghdr rights_send = {
        .msg_iov = &rights_send_iov,
        .msg_iovlen = 1,
        .msg_control = rights_control,
        .msg_controllen = sizeof(rights_control),
    };
    struct cmsghdr *rights_send_cmsg = CMSG_FIRSTHDR(&rights_send);
    if (!rights_send_cmsg) {
        return 120;
    }
    rights_send_cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    rights_send_cmsg->cmsg_level = SOL_SOCKET;
    rights_send_cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(rights_send_cmsg), &transfer_pipe[0], sizeof(int));
    if (sendmsg(rights_fds[0], &rights_send, MSG_NOSIGNAL) != 1 ||
        close(transfer_pipe[0]) != 0) {
        return 121;
    }
    memset(rights_control, 0, sizeof(rights_control));
    char rights_receive_byte = 0;
    struct iovec rights_receive_iov = {
        .iov_base = &rights_receive_byte,
        .iov_len = 1,
    };
    struct msghdr rights_receive = {
        .msg_iov = &rights_receive_iov,
        .msg_iovlen = 1,
        .msg_control = rights_control,
        .msg_controllen = sizeof(rights_control),
    };
    if (recvmsg(rights_fds[1], &rights_receive, MSG_CMSG_CLOEXEC) != 1 ||
        rights_receive_byte != 'R') {
        return 122;
    }
    struct cmsghdr *rights_receive_cmsg = CMSG_FIRSTHDR(&rights_receive);
    if (!rights_receive_cmsg ||
        rights_receive_cmsg->cmsg_level != SOL_SOCKET ||
        rights_receive_cmsg->cmsg_type != SCM_RIGHTS ||
        rights_receive_cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
        return 123;
    }
    int received_pipe_read = -1;
    memcpy(&received_pipe_read, CMSG_DATA(rights_receive_cmsg),
           sizeof(received_pipe_read));
    if (received_pipe_read < 0 ||
        (fcntl(received_pipe_read, F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(received_pipe_read, F_GETFL) & O_NONBLOCK) == 0 ||
        write(transfer_pipe[1], "T", 1) != 1 ||
        read(received_pipe_read, blocking_bytes, 1) != 1 ||
        blocking_bytes[0] != 'T' ||
        close(received_pipe_read) != 0 ||
        close(transfer_pipe[1]) != 0 ||
        close(rights_fds[0]) != 0 || close(rights_fds[1]) != 0) {
        return 124;
    }
    int cross_rights[2];
    int cross_pipe[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, cross_rights) != 0 ||
        pipe2(cross_pipe, O_NONBLOCK) != 0) {
        return 125;
    }
    pid_t rights_child = fork();
    if (rights_child < 0) {
        return 126;
    }
    if (rights_child == 0) {
        close(cross_rights[0]);
        close(cross_pipe[0]);
        char prefix = 0;
        if (recv(cross_rights[1], &prefix, 1, 0) != 1 || prefix != 'P') {
            _exit(127);
        }
        memset(rights_control, 0, sizeof(rights_control));
        rights_receive_byte = 0;
        rights_receive = (struct msghdr){
            .msg_iov = &rights_receive_iov,
            .msg_iovlen = 1,
            .msg_control = rights_control,
            .msg_controllen = sizeof(rights_control),
        };
        if (recvmsg(cross_rights[1], &rights_receive,
                    MSG_CMSG_CLOEXEC) != 1 ||
            rights_receive_byte != 'C') {
            _exit(128);
        }
        rights_receive_cmsg = CMSG_FIRSTHDR(&rights_receive);
        if (!rights_receive_cmsg ||
            rights_receive_cmsg->cmsg_type != SCM_RIGHTS ||
            rights_receive_cmsg->cmsg_len != CMSG_LEN(sizeof(int))) {
            _exit(129);
        }
        received_pipe_read = -1;
        memcpy(&received_pipe_read, CMSG_DATA(rights_receive_cmsg),
               sizeof(received_pipe_read));
        if (received_pipe_read < 0 ||
            (fcntl(received_pipe_read, F_GETFD) & FD_CLOEXEC) == 0 ||
            (fcntl(received_pipe_read, F_GETFL) & O_NONBLOCK) == 0 ||
            read(received_pipe_read, blocking_bytes, 1) != 1 ||
            blocking_bytes[0] != 'C') {
            _exit(130);
        }
        close(received_pipe_read);
        close(cross_pipe[1]);
        close(cross_rights[1]);
        _exit(0);
    }
    close(cross_rights[1]);
    memset(rights_control, 0, sizeof(rights_control));
    rights_control[0] = 0;
    rights_byte = 'C';
    rights_send_iov.iov_base = &rights_byte;
    rights_send_iov.iov_len = 1;
    rights_send = (struct msghdr){
        .msg_iov = &rights_send_iov,
        .msg_iovlen = 1,
        .msg_control = rights_control,
        .msg_controllen = sizeof(rights_control),
    };
    rights_send_cmsg = CMSG_FIRSTHDR(&rights_send);
    if (!rights_send_cmsg) {
        return 131;
    }
    rights_send_cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    rights_send_cmsg->cmsg_level = SOL_SOCKET;
    rights_send_cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(rights_send_cmsg), &cross_pipe[0], sizeof(int));
    if (write(cross_rights[0], "P", 1) != 1 ||
        sendmsg(cross_rights[0], &rights_send, MSG_NOSIGNAL) != 1 ||
        close(cross_pipe[0]) != 0 ||
        write(cross_pipe[1], "C", 1) != 1 ||
        close(cross_pipe[1]) != 0 ||
        close(cross_rights[0]) != 0) {
        return 132;
    }
    int rights_status = 0;
    if (waitpid(rights_child, &rights_status, 0) != rights_child ||
        !WIFEXITED(rights_status) || WEXITSTATUS(rights_status) != 0) {
        return 133;
    }
    int credential_fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, credential_fds) != 0) {
        return 137;
    }
    pid_t credential_parent_pid = getpid();
    pid_t credential_child = fork();
    if (credential_child < 0) {
        return 138;
    }
    if (credential_child == 0) {
        close(credential_fds[0]);
        int passcred = 1;
        char credential_control[CMSG_SPACE(sizeof(struct ucred))];
        memset(credential_control, 0, sizeof(credential_control));
        char credential_byte = 0;
        struct iovec credential_iov = {
            .iov_base = &credential_byte,
            .iov_len = 1,
        };
        struct msghdr credential_message = {
            .msg_iov = &credential_iov,
            .msg_iovlen = 1,
            .msg_control = credential_control,
            .msg_controllen = sizeof(credential_control),
        };
        if (setsockopt(credential_fds[1], SOL_SOCKET, SO_PASSCRED,
                       &passcred, sizeof(passcred)) != 0 ||
            recvmsg(credential_fds[1], &credential_message, 0) != 1 ||
            credential_byte != 'D') {
            _exit(139);
        }
        struct cmsghdr *credential_cmsg =
            CMSG_FIRSTHDR(&credential_message);
        struct ucred received_cred;
        if (!credential_cmsg ||
            credential_cmsg->cmsg_level != SOL_SOCKET ||
            credential_cmsg->cmsg_type != SCM_CREDENTIALS ||
            credential_cmsg->cmsg_len != CMSG_LEN(sizeof(received_cred))) {
            _exit(140);
        }
        memcpy(&received_cred, CMSG_DATA(credential_cmsg),
               sizeof(received_cred));
        if (received_cred.pid != credential_parent_pid ||
            received_cred.uid != 0 || received_cred.gid != 0) {
            _exit(141);
        }
        close(credential_fds[1]);
        _exit(0);
    }
    close(credential_fds[1]);
    char credential_control[CMSG_SPACE(sizeof(struct ucred))];
    memset(credential_control, 0, sizeof(credential_control));
    char credential_byte = 'D';
    struct iovec credential_iov = {
        .iov_base = &credential_byte,
        .iov_len = 1,
    };
    struct msghdr credential_message = {
        .msg_iov = &credential_iov,
        .msg_iovlen = 1,
        .msg_control = credential_control,
        .msg_controllen = sizeof(credential_control),
    };
    struct cmsghdr *credential_cmsg = CMSG_FIRSTHDR(&credential_message);
    struct ucred sent_cred = {
        .pid = credential_parent_pid,
        .uid = 0,
        .gid = 0,
    };
    if (!credential_cmsg) {
        return 142;
    }
    credential_cmsg->cmsg_len = CMSG_LEN(sizeof(sent_cred));
    credential_cmsg->cmsg_level = SOL_SOCKET;
    credential_cmsg->cmsg_type = SCM_CREDENTIALS;
    memcpy(CMSG_DATA(credential_cmsg), &sent_cred, sizeof(sent_cred));
    if (sendmsg(credential_fds[0], &credential_message, MSG_NOSIGNAL) != 1 ||
        close(credential_fds[0]) != 0) {
        return 143;
    }
    int credential_status = 0;
    if (waitpid(credential_child, &credential_status, 0) != credential_child ||
        !WIFEXITED(credential_status) ||
        WEXITSTATUS(credential_status) != 0) {
        return 144;
    }
    int ashmem_fd = open("/dev/ashmem", O_RDWR | O_CLOEXEC);
    char ashmem_name[256] = "jasper-ashmem";
    size_t ashmem_size = 8192;
    size_t ashmem_requested = 0;
    size_t ashmem_protection = PROT_READ | PROT_WRITE;
    if (ashmem_fd < 0 ||
        (fcntl(ashmem_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_SET_NAME, ashmem_name) != 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_SET_PROT_MASK,
              &ashmem_protection) != 0) {
        return 145;
    }
    memset(ashmem_name, 0, sizeof(ashmem_name));
    if (ioctl(ashmem_fd, JASPER_ASHMEM_GET_NAME, ashmem_name) != 0 ||
        strcmp(ashmem_name, "jasper-ashmem") != 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_SET_SIZE, &ashmem_size) != 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_GET_SIZE, &ashmem_requested) != 0 ||
        ashmem_requested != ashmem_size ||
        ioctl(ashmem_fd, JASPER_ASHMEM_GET_PROT_MASK,
              &ashmem_protection) != 0 ||
        ashmem_protection != (PROT_READ | PROT_WRITE)) {
        return 146;
    }
    struct stat ashmem_stat;
    struct statfs ashmem_statfs;
    if (fstat(ashmem_fd, &ashmem_stat) != 0 ||
        !S_ISCHR(ashmem_stat.st_mode) ||
        ashmem_stat.st_size != (off_t)ashmem_size ||
        fstatfs(ashmem_fd, &ashmem_statfs) != 0 ||
        ashmem_statfs.f_bsize != 4096) {
        return 177;
    }
    size_t pin_length = ashmem_size;
    unsigned int pin_status = 0;
    if (ioctl(ashmem_fd, JASPER_ASHMEM_PIN, &pin_length) < 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_PIN, &pin_length) < 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_GET_PIN_STATUS, &pin_status) != 0 ||
        pin_status != 2 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_UNPIN, &pin_length) < 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_UNPIN, &pin_length) < 0 ||
        ioctl(ashmem_fd, JASPER_ASHMEM_GET_PIN_STATUS, &pin_status) != 0 ||
        pin_status != 0) {
        return 147;
    }
    int to_child[2];
    int to_parent[2];
    if (pipe2(to_child, 0) != 0 || pipe2(to_parent, 0) != 0) {
        return 148;
    }
    pid_t ashmem_child = fork();
    if (ashmem_child < 0) {
        return 149;
    }
    if (ashmem_child == 0) {
        close(to_child[1]);
        close(to_parent[0]);
        unsigned char *shared = mmap(NULL, ashmem_size,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     ashmem_fd, 0);
        char token = 0;
        if (shared == MAP_FAILED ||
            read(to_child[0], &token, 1) != 1 || token != 'M' ||
            shared[0] != 'A') {
            _exit(150);
        }
        shared[4096] = 'B';
        if (msync(shared, ashmem_size, MS_SYNC) != 0 ||
            write(to_parent[1], "K", 1) != 1 ||
            munmap(shared, ashmem_size) != 0) {
            _exit(151);
        }
        close(to_child[0]);
        close(to_parent[1]);
        close(ashmem_fd);
        _exit(0);
    }
    close(to_child[0]);
    close(to_parent[1]);
    unsigned char *shared = mmap(NULL, ashmem_size,
                                 PROT_READ | PROT_WRITE, MAP_SHARED,
                                 ashmem_fd, 0);
    if (shared == MAP_FAILED || shared[0] != 0 || shared[4096] != 0) {
        return 152;
    }
    shared[0] = 'A';
    unsigned char ashmem_residency[2] = {0};
    if (msync(shared, ashmem_size, MS_SYNC) != 0 ||
        mincore(shared, ashmem_size, ashmem_residency) != 0 ||
        ashmem_residency[0] != 1 || ashmem_residency[1] != 1) {
        return 201;
    }
    char token[2] = {0};
    if (write(to_child[1], "M", 1) != 1 ||
        read(to_parent[0], token, 1) != 1 || token[0] != 'K' ||
        shared[4096] != 'B' ||
        munmap(shared, ashmem_size) != 0) {
        return 153;
    }
    int ashmem_status = 0;
    if (waitpid(ashmem_child, &ashmem_status, 0) != ashmem_child ||
        !WIFEXITED(ashmem_status) || WEXITSTATUS(ashmem_status) != 0 ||
        close(to_child[1]) != 0 || close(to_parent[0]) != 0 ||
        close(ashmem_fd) != 0) {
        return 154;
    }
    int memfd = memfd_create("jasper-memfd",
                             MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) {
        printf("memfd-create-fail fd=%d errno=%d\n", memfd, errno);
        return 207;
    }
    int memfd_flags = fcntl(memfd, F_GETFD);
    if (memfd_flags < 0) {
        printf("memfd-fcntl-fail fd=%d errno=%d\n", memfd, errno);
        return 207;
    }
    if ((memfd_flags & FD_CLOEXEC) == 0) {
        printf("memfd-cloexec-fail fd=%d flags=%d\n", memfd, memfd_flags);
        return 207;
    }
    errno = 0;
    if (ftruncate(memfd, 16) != 0) {
        printf("memfd-truncate-fail fd=%d errno=%d\n", memfd, errno);
        return 207;
    }
    unsigned char memfd_io[64] = {0};
    unsigned char memfd_pread[4] = {0};
    int memfd_seals_before_write = fcntl(memfd, F_GET_SEALS);
    errno = 0;
    ssize_t memfd_pwrite_result = pwrite(memfd, "WXYZ", 4, 4);
    int memfd_pwrite_errno = errno;
    errno = 0;
    ssize_t memfd_pread_result =
        pread(memfd, memfd_pread, sizeof(memfd_pread), 4);
    int memfd_pread_errno = errno;
    errno = 0;
    off_t memfd_seek_result = lseek(memfd, 16, SEEK_SET);
    int memfd_seek_errno = errno;
    errno = 0;
    ssize_t memfd_write_result = write(memfd, "!", 1);
    int memfd_write_errno = errno;
    if (memfd_pwrite_result != 4 || memfd_pwrite_errno != 0 ||
        memfd_pread_result != 4 || memfd_pread_errno != 0 ||
        memcmp(memfd_pread, "WXYZ", 4) != 0 ||
        memfd_seek_result != 16 || memfd_seek_errno != 0 ||
        memfd_write_result != 1 || memfd_write_errno != 0) {
        printf("memfd-positioned-io-fail seals=%d write=%zd/%d read=%zd/%d "
               "data=%02x%02x%02x%02x seek=%lld/%d append=%zd/%d\n",
               memfd_seals_before_write,
               memfd_pwrite_result, memfd_pwrite_errno,
               memfd_pread_result, memfd_pread_errno,
               memfd_pread[0], memfd_pread[1],
               memfd_pread[2], memfd_pread[3],
               (long long)memfd_seek_result, memfd_seek_errno,
               memfd_write_result, memfd_write_errno);
        return 244;
    }
    struct iovec memfd_vectors[2] = {
        {.iov_base = "EN", .iov_len = 2},
        {.iov_base = "D!", .iov_len = 2},
    };
    if (lseek(memfd, 17, SEEK_SET) != 17 ||
        writev(memfd, memfd_vectors, 2) != 4 ||
        lseek(memfd, 0, SEEK_SET) != 0) {
        printf("memfd-writev-fail errno=%d\n", errno);
        return 245;
    }
    struct iovec memfd_read_vectors[2] = {
        {.iov_base = memfd_io, .iov_len = 8},
        {.iov_base = memfd_io + 8, .iov_len = 13},
    };
    if (readv(memfd, memfd_read_vectors, 2) != 21 ||
        memcmp(memfd_io + 4, "WXYZ", 4) != 0 ||
        memcmp(memfd_io + 16, "!END!", 5) != 0) {
        printf("memfd-readv-fail errno=%d\n", errno);
        return 246;
    }
    struct iovec positioned_write_vectors[2] = {
        {.iov_base = "PV", .iov_len = 2},
        {.iov_base = "2", .iov_len = 1},
    };
    struct iovec positioned_read_vectors[2] = {
        {.iov_base = memfd_io + 32, .iov_len = 2},
        {.iov_base = memfd_io + 34, .iov_len = 1},
    };
    if (syscall(SYS_pwritev, memfd, positioned_write_vectors, 2, 32) != 3 ||
        syscall(SYS_preadv, memfd, positioned_read_vectors, 2, 32) != 3 ||
        memcmp(memfd_io + 32, "PV2", 3) != 0) {
        printf("memfd-positioned-vector-fail errno=%d\n", errno);
        return 247;
    }
    positioned_write_vectors[0].iov_base = "V2";
    positioned_write_vectors[1].iov_len = 0;
    positioned_read_vectors[0].iov_base = memfd_io + 40;
    positioned_read_vectors[0].iov_len = 2;
    positioned_read_vectors[1].iov_len = 0;
    if (syscall(SYS_pwritev2, memfd, positioned_write_vectors, 2, 40, 0) != 2 ||
        syscall(SYS_preadv2, memfd, positioned_read_vectors, 2, 40, 0) != 2 ||
        memcmp(memfd_io + 40, "V2", 2) != 0 ||
        ftruncate(memfd, 4096) != 0) {
        printf("memfd-vector2-fail errno=%d\n", errno);
        return 248;
    }
    struct stat memfd_stat;
    if (fstat(memfd, &memfd_stat) != 0 || !S_ISREG(memfd_stat.st_mode) ||
        memfd_stat.st_size != 4096) {
        return 208;
    }
    unsigned char *memfd_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                    MAP_SHARED, memfd, 0);
    if (memfd_map == MAP_FAILED || memfd_map[0] != 0 ||
        memcmp(memfd_map + 4, "WXYZ", 4) != 0 ||
        memcmp(memfd_map + 16, "!END!", 5) != 0) {
        return 209;
    }
    memfd_map[0] = 'M';
    if (msync(memfd_map, 4096, MS_SYNC) != 0 ||
        fcntl(memfd, F_ADD_SEALS, F_SEAL_GROW) != 0 ||
        fcntl(memfd, F_GET_SEALS) != F_SEAL_GROW) {
        return 210;
    }
    errno = 0;
    if (ftruncate(memfd, 8192) != -1 || errno != EPERM) {
        return 211;
    }
    errno = 0;
    if (fcntl(memfd, F_ADD_SEALS, F_SEAL_WRITE) != -1 || errno != EBUSY ||
        munmap(memfd_map, 4096) != 0 ||
        fcntl(memfd, F_ADD_SEALS, F_SEAL_WRITE) != 0 ||
        fcntl(memfd, F_GET_SEALS) != (F_SEAL_GROW | F_SEAL_WRITE)) {
        return 212;
    }
    errno = 0;
    ssize_t memfd_sealed_write = pwrite(memfd, "S", 1, 0);
    int memfd_sealed_write_errno = errno;
    if (memfd_sealed_write != -1 || memfd_sealed_write_errno != EPERM) {
        printf("memfd-sealed-pwrite-fail result=%zd errno=%d\n",
               memfd_sealed_write, memfd_sealed_write_errno);
        return 249;
    }
    errno = 0;
    memfd_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
                     memfd, 0);
    if (memfd_map != MAP_FAILED || errno != EPERM) {
        printf("memfd-seal-map-fail result=%p errno=%d\n",
               (void *)memfd_map, errno);
        return 213;
    }
    memfd_map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, memfd, 0);
    if (memfd_map == MAP_FAILED || memfd_map[0] != 'M' ||
        munmap(memfd_map, 4096) != 0 || close(memfd) != 0) {
        return 214;
    }
    unsigned char *remap_pages = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remap_pages == MAP_FAILED) {
        return 294;
    }
    memcpy(remap_pages, "GROW", 4);
    remap_pages = mremap(remap_pages, 4096, 8192, 0);
    if (remap_pages == MAP_FAILED ||
        memcmp(remap_pages, "GROW", 4) != 0 || remap_pages[4096] != 0) {
        return 295;
    }
    remap_pages[4096] = 'N';
    remap_pages = mremap(remap_pages, 8192, 4096, 0);
    if (remap_pages == MAP_FAILED ||
        memcmp(remap_pages, "GROW", 4) != 0 ||
        munmap(remap_pages, 4096) != 0) {
        return 296;
    }
    unsigned char *remap_target =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remap_target == MAP_FAILED || munmap(remap_target, 8192) != 0) {
        return 297;
    }
    unsigned char *remap_source = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (remap_source == MAP_FAILED) {
        return 298;
    }
    strcpy((char *)remap_source, "MOVE");
    unsigned char *remap_moved =
        mremap(remap_source, 4096, 8192, MREMAP_MAYMOVE | MREMAP_FIXED,
               remap_target);
    if (remap_moved != remap_target ||
        memcmp(remap_moved, "MOVE", 5) != 0 ||
        munmap(remap_moved, 8192) != 0) {
        return 299;
    }
    futex_word = 0;
    atomic_store(&futex_started, 0);
    atomic_store(&futex_finished, 0);
    pthread_t futex_threads[2];
    struct futex_thread_arg futex_args[2] = {
        {.bitset = 0x1},
        {.bitset = 0x2},
    };
    if (pthread_create(&futex_threads[0], NULL, futex_waiter,
                       &futex_args[0]) != 0 ||
        pthread_create(&futex_threads[1], NULL, futex_waiter,
                       &futex_args[1]) != 0) {
        return 300;
    }
    while (atomic_load_explicit(&futex_started, memory_order_acquire) != 2) {
        sched_yield();
    }
    if (syscall(SYS_futex, &futex_word,
                FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1,
                NULL, NULL, 0x1) != 1) {
        return 301;
    }
    struct timespec futex_delay = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&futex_delay, NULL);
    if (atomic_load_explicit(&futex_finished, memory_order_acquire) != 1) {
        return 302;
    }
    if (syscall(SYS_futex, &futex_word,
                FUTEX_WAKE_BITSET | FUTEX_PRIVATE_FLAG, 1,
                NULL, NULL, 0x2) != 1) {
        return 303;
    }
    void *futex_result0 = NULL;
    void *futex_result1 = NULL;
    if (pthread_join(futex_threads[0], &futex_result0) != 0 ||
        pthread_join(futex_threads[1], &futex_result1) != 0 ||
        futex_result0 != 0 || futex_result1 != 0 ||
        atomic_load_explicit(&futex_finished, memory_order_acquire) != 2) {
        return 304;
    }
    futex_word = 0;
    struct timespec futex_relative = {.tv_sec = 0, .tv_nsec = 20000000};
    errno = 0;
    if (syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                0, &futex_relative, NULL, 0) != -1 ||
        errno != ETIMEDOUT) {
        return 305;
    }
    struct timespec futex_absolute;
    clock_gettime(CLOCK_MONOTONIC, &futex_absolute);
    futex_absolute.tv_nsec += 20000000;
    if (futex_absolute.tv_nsec >= 1000000000) {
        futex_absolute.tv_sec++;
        futex_absolute.tv_nsec -= 1000000000;
    }
    errno = 0;
    if (syscall(SYS_futex, &futex_word,
                FUTEX_WAIT_BITSET | FUTEX_PRIVATE_FLAG,
                0, &futex_absolute, NULL, 0x1) != -1 ||
        errno != ETIMEDOUT) {
        return 306;
    }
    errno = 0;
    if (syscall(SYS_futex, &futex_word, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                1, NULL, NULL, 0) != -1 || errno != EAGAIN) {
        return 307;
    }
    int shared_futex_fd = memfd_create("shared-futex", 0);
    if (shared_futex_fd < 0 || ftruncate(shared_futex_fd, 4096) != 0) {
        return 308;
    }
    uint32_t *shared_futex_word =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED,
             shared_futex_fd, 0);
    int shared_futex_ready[2];
    if (shared_futex_word == MAP_FAILED ||
        pipe2(shared_futex_ready, 0) != 0) {
        return 309;
    }
    *shared_futex_word = 0;
    pid_t shared_futex_child = fork();
    if (shared_futex_child < 0) {
        return 310;
    }
    if (shared_futex_child == 0) {
        close(shared_futex_ready[0]);
        char ready = 'F';
        if (write(shared_futex_ready[1], &ready, 1) != 1) {
            _exit(311);
        }
        struct timespec shared_timeout = {.tv_sec = 0, .tv_nsec = 500000000};
        long wait_result =
            syscall(SYS_futex, shared_futex_word, FUTEX_WAIT, 0,
                    &shared_timeout, NULL, 0);
        _exit(wait_result == 0 ? 0 : 312);
    }
    close(shared_futex_ready[1]);
    char shared_ready = 0;
    struct timespec shared_delay = {.tv_sec = 0, .tv_nsec = 30000000};
    if (read(shared_futex_ready[0], &shared_ready, 1) != 1 ||
        shared_ready != 'F') {
        return 313;
    }
    nanosleep(&shared_delay, NULL);
    if (syscall(SYS_futex, shared_futex_word, FUTEX_WAKE, 1,
                NULL, NULL, 0) != 1) {
        return 314;
    }
    int shared_futex_status = 0;
    if (waitpid(shared_futex_child, &shared_futex_status, 0) !=
            shared_futex_child ||
        !WIFEXITED(shared_futex_status) ||
        WEXITSTATUS(shared_futex_status) != 0 ||
        close(shared_futex_ready[0]) != 0 ||
        munmap(shared_futex_word, 4096) != 0 ||
        close(shared_futex_fd) != 0) {
        return 315;
    }
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    int epoll_pipe[2];
    struct epoll_event epoll_ready[128] = {0};
    if (epfd < 0 || (fcntl(epfd, F_GETFD) & FD_CLOEXEC) == 0 ||
        pipe2(epoll_pipe, 0) != 0 ||
        epoll_wait(epfd, epoll_ready, 128, 20) != 0) {
        return 250;
    }
    struct epoll_event epoll_interest = {
        .events = EPOLLIN,
        .data.u64 = 0x4a5345504f4c4cULL,
    };
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, epoll_pipe[0],
                  &epoll_interest) != 0) {
        return 251;
    }
    pid_t epoll_child = fork();
    if (epoll_child < 0) {
        return 252;
    }
    if (epoll_child == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&delay, NULL);
        _exit(write(epoll_pipe[1], "E", 1) == 1 ? 0 : 1);
    }
    memset(epoll_ready, 0, sizeof(epoll_ready));
    if (epoll_wait(epfd, epoll_ready, 1, 300) != 1 ||
        (epoll_ready[0].events & EPOLLIN) == 0 ||
        epoll_ready[0].data.u64 != 0x4a5345504f4c4cULL ||
        read(epoll_pipe[0], memfd_io, 1) != 1 ||
        memfd_io[0] != 'E') {
        return 253;
    }
    int epoll_child_status = 0;
    if (waitpid(epoll_child, &epoll_child_status, 0) != epoll_child ||
        !WIFEXITED(epoll_child_status) || WEXITSTATUS(epoll_child_status) != 0 ||
        epoll_ctl(epfd, EPOLL_CTL_DEL, epoll_pipe[0], NULL) != 0 ||
        close(epoll_pipe[0]) != 0 || close(epoll_pipe[1]) != 0) {
        return 254;
    }
    int epoll_event_fd = eventfd(0, EFD_NONBLOCK);
    uint64_t epoll_counter = 1;
    epoll_interest.events = EPOLLIN | EPOLLET;
    epoll_interest.data.u64 = 0x45504f4c4c4554ULL;
    if (epoll_event_fd < 0 ||
        epoll_ctl(epfd, EPOLL_CTL_ADD, epoll_event_fd,
                  &epoll_interest) != 0 ||
        write(epoll_event_fd, &epoll_counter, sizeof(epoll_counter)) !=
            sizeof(epoll_counter) ||
        epoll_wait(epfd, epoll_ready, 1, 30) != 1 ||
        epoll_ready[0].data.u64 != 0x45504f4c4c4554ULL ||
        epoll_wait(epfd, epoll_ready, 1, 0) != 0 ||
        read(epoll_event_fd, &epoll_counter, sizeof(epoll_counter)) !=
            sizeof(epoll_counter)) {
        return 255;
    }
    epoll_interest.events = EPOLLIN | EPOLLONESHOT;
    epoll_interest.data.u64 = 0x4f4e4553484f54ULL;
    if (epoll_ctl(epfd, EPOLL_CTL_MOD, epoll_event_fd,
                  &epoll_interest) != 0) {
        return 256;
    }
    epoll_counter = 1;
    if (write(epoll_event_fd, &epoll_counter, sizeof(epoll_counter)) !=
            sizeof(epoll_counter) ||
        epoll_wait(epfd, epoll_ready, 1, 30) != 1 ||
        epoll_ready[0].data.u64 != 0x4f4e4553484f54ULL ||
        epoll_wait(epfd, epoll_ready, 1, 0) != 0 ||
        epoll_ctl(epfd, EPOLL_CTL_MOD, epoll_event_fd,
                  &epoll_interest) != 0 ||
        epoll_wait(epfd, epoll_ready, 1, 0) != 1 ||
        read(epoll_event_fd, &epoll_counter, sizeof(epoll_counter)) !=
            sizeof(epoll_counter)) {
        return 257;
    }
    struct timespec epoll_timeout = {.tv_sec = 0, .tv_nsec = 20000000};
    if (epoll_ctl(epfd, EPOLL_CTL_DEL, epoll_event_fd, NULL) != 0 ||
        syscall(SYS_epoll_pwait2, epfd, epoll_ready, 1,
                &epoll_timeout, NULL, 0) != 0 ||
        close(epoll_event_fd) != 0) {
        return 258;
    }
    sigset_t epoll_old_mask;
    sigset_t epoll_blocked_mask;
    sigset_t epoll_empty_mask;
    sigemptyset(&epoll_blocked_mask);
    sigaddset(&epoll_blocked_mask, SIGUSR2);
    sigemptyset(&epoll_empty_mask);
    if (signal(SIGUSR2, signal_noop) == SIG_ERR ||
        sigprocmask(SIG_BLOCK, &epoll_blocked_mask, &epoll_old_mask) != 0) {
        return 259;
    }
    pid_t epoll_signal_child = fork();
    if (epoll_signal_child < 0) {
        return 260;
    }
    if (epoll_signal_child == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&delay, NULL);
        _exit(kill(getppid(), SIGUSR2) == 0 ? 0 : 1);
    }
    errno = 0;
    long epoll_signal_result = syscall(SYS_epoll_pwait, epfd, epoll_ready, 1,
                                      100, &epoll_empty_mask,
                                      sizeof(uint64_t));
    int epoll_signal_errno = errno;
    if (epoll_signal_result != -1 || epoll_signal_errno != EINTR ||
        sigprocmask(SIG_SETMASK, &epoll_old_mask, NULL) != 0) {
        printf("epoll-pwait-signal-fail result=%ld errno=%d\n",
               epoll_signal_result, epoll_signal_errno);
        return 261;
    }
    waitpid(epoll_signal_child, &epoll_child_status, 0);
    if (!WIFEXITED(epoll_child_status) || WEXITSTATUS(epoll_child_status) != 0 ||
        close(epfd) != 0) {
        return 262;
    }
    struct io_uring_params uring_params = {0};
    int uring_fd = syscall(SYS_io_uring_setup, 8, &uring_params);
    if (uring_fd < 0 || uring_params.sq_entries != 8 ||
        uring_params.cq_entries != 16 ||
        (uring_params.features & IORING_FEAT_SINGLE_MMAP) == 0) {
        return 268;
    }
    size_t uring_sq_size =
        uring_params.sq_off.array +
        uring_params.sq_entries * sizeof(unsigned);
    size_t uring_cq_size =
        uring_params.cq_off.cqes +
        uring_params.cq_entries * sizeof(struct io_uring_cqe);
    size_t uring_ring_size =
        uring_sq_size > uring_cq_size ? uring_sq_size : uring_cq_size;
    unsigned char *uring_sq = mmap(NULL, uring_ring_size, PROT_READ | PROT_WRITE,
                                   MAP_SHARED, uring_fd, IORING_OFF_SQ_RING);
    struct io_uring_sqe *uring_sqes =
        mmap(NULL, uring_params.sq_entries * sizeof(struct io_uring_sqe),
             PROT_READ | PROT_WRITE, MAP_SHARED, uring_fd, IORING_OFF_SQES);
    if (uring_sq == MAP_FAILED || uring_sqes == MAP_FAILED) {
        return 269;
    }
    unsigned *uring_sq_head = (unsigned *)(uring_sq + uring_params.sq_off.head);
    unsigned *uring_sq_tail = (unsigned *)(uring_sq + uring_params.sq_off.tail);
    unsigned *uring_sq_mask = (unsigned *)(uring_sq + uring_params.sq_off.ring_mask);
    unsigned *uring_sq_array = (unsigned *)(uring_sq + uring_params.sq_off.array);
    unsigned *uring_cq_head = (unsigned *)(uring_sq + uring_params.cq_off.head);
    unsigned *uring_cq_tail = (unsigned *)(uring_sq + uring_params.cq_off.tail);
    unsigned uring_index = *uring_sq_tail & *uring_sq_mask;
    memset(&uring_sqes[uring_index], 0, sizeof(uring_sqes[uring_index]));
    uring_sqes[uring_index].opcode = IORING_OP_NOP;
    uring_sqes[uring_index].user_data = 0x4e4f5049ULL;
    uring_sq_array[uring_index] = uring_index;
    __sync_synchronize();
    *uring_sq_tail = *uring_sq_tail + 1;
    if (syscall(SYS_io_uring_enter, uring_fd, 1, 0, 0, NULL, 0) != 1 ||
        *uring_sq_head != 1 || *uring_cq_tail != 1) {
        return 270;
    }
    struct io_uring_cqe *uring_cqe =
        (struct io_uring_cqe *)(uring_sq + uring_params.cq_off.cqes) +
        (*uring_cq_head & (uring_params.cq_entries - 1));
    if (uring_cqe->user_data != 0x4e4f5049ULL || uring_cqe->res != 0) {
        return 271;
    }
    *uring_cq_head = *uring_cq_head + 1;
    int uring_pipe[2];
    if (pipe2(uring_pipe, 0) != 0) {
        return 272;
    }
    uring_index = *uring_sq_tail & *uring_sq_mask;
    memset(&uring_sqes[uring_index], 0, sizeof(uring_sqes[uring_index]));
    uring_sqes[uring_index].opcode = IORING_OP_WRITE;
    uring_sqes[uring_index].fd = uring_pipe[1];
    uring_sqes[uring_index].addr = (uint64_t)(uintptr_t)"uring-io";
    uring_sqes[uring_index].len = 8;
    uring_sqes[uring_index].off = UINT64_MAX;
    uring_sqes[uring_index].user_data = 0x57524954ULL;
    uring_sq_array[uring_index] = uring_index;
    __sync_synchronize();
    *uring_sq_tail = *uring_sq_tail + 1;
    if (syscall(SYS_io_uring_enter, uring_fd, 1, 0, IORING_ENTER_GETEVENTS,
                NULL, 0) != 1) {
        return 273;
    }
    uring_cqe = (struct io_uring_cqe *)(uring_sq + uring_params.cq_off.cqes) +
                (*uring_cq_head & (uring_params.cq_entries - 1));
    if (uring_cqe->user_data != 0x57524954ULL || uring_cqe->res != 8) {
        return 274;
    }
    *uring_cq_head = *uring_cq_head + 1;
    uring_index = *uring_sq_tail & *uring_sq_mask;
    memset(&uring_sqes[uring_index], 0, sizeof(uring_sqes[uring_index]));
    uring_sqes[uring_index].opcode = IORING_OP_READ;
    uring_sqes[uring_index].fd = uring_pipe[0];
    uring_sqes[uring_index].addr = (uint64_t)(uintptr_t)memfd_io;
    uring_sqes[uring_index].len = 8;
    uring_sqes[uring_index].off = UINT64_MAX;
    uring_sqes[uring_index].user_data = 0x52454144ULL;
    uring_sq_array[uring_index] = uring_index;
    __sync_synchronize();
    *uring_sq_tail = *uring_sq_tail + 1;
    if (syscall(SYS_io_uring_enter, uring_fd, 1, 0, IORING_ENTER_GETEVENTS,
                NULL, 0) != 1) {
        return 275;
    }
    uring_cqe = (struct io_uring_cqe *)(uring_sq + uring_params.cq_off.cqes) +
                (*uring_cq_head & (uring_params.cq_entries - 1));
    if (uring_cqe->user_data != 0x52454144ULL || uring_cqe->res != 8 ||
        memcmp(memfd_io, "uring-io", 8) != 0) {
        return 276;
    }
    *uring_cq_head = *uring_cq_head + 1;
    uring_index = *uring_sq_tail & *uring_sq_mask;
    memset(&uring_sqes[uring_index], 0, sizeof(uring_sqes[uring_index]));
    uring_sqes[uring_index].opcode = IORING_OP_NOP;
    uring_sqes[uring_index].user_data = 0x494e56414c4944ULL;
    uring_sq_array[uring_index] = uring_params.sq_entries;
    __sync_synchronize();
    *uring_sq_tail = *uring_sq_tail + 1;
    long uring_invalid_enter =
        syscall(SYS_io_uring_enter, uring_fd, 1, 0,
                IORING_ENTER_GETEVENTS, NULL, 0);
    if (uring_invalid_enter != 1) {
        printf("io-uring-invalid-enter result=%ld errno=%d\n",
               uring_invalid_enter, errno);
        return 278;
    }
    uring_cqe = (struct io_uring_cqe *)(uring_sq + uring_params.cq_off.cqes) +
                (*uring_cq_head & (uring_params.cq_entries - 1));
    if (uring_cqe->res != -EINVAL) {
        printf("io-uring-invalid-cqe data=%llx res=%d head=%u tail=%u\n",
               (unsigned long long)uring_cqe->user_data, uring_cqe->res,
               *uring_cq_head, *uring_cq_tail);
        return 279;
    }
    *uring_cq_head = *uring_cq_head + 1;
    int uring_unmap_sqes =
        munmap(uring_sqes,
               uring_params.sq_entries * sizeof(struct io_uring_sqe));
    int uring_unmap_ring = munmap(uring_sq, uring_ring_size);
    int uring_close_read = close(uring_pipe[0]);
    int uring_close_write = close(uring_pipe[1]);
    int uring_close = close(uring_fd);
    if (uring_unmap_sqes != 0 || uring_unmap_ring != 0 ||
        uring_close_read != 0 || uring_close_write != 0 ||
        uring_close != 0) {
        printf("io-uring-cleanup-fail sqes=%d ring=%d read=%d "
               "write=%d ringfd=%d errno=%d\n",
               uring_unmap_sqes, uring_unmap_ring,
               uring_close_read, uring_close_write, uring_close, errno);
        return 277;
    }
    int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    struct binder_version binder_version = {0};
    uint32_t binder_threads = 4;
    if (binder_fd < 0 ||
        (fcntl(binder_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        ioctl(binder_fd, BINDER_VERSION, &binder_version) != 0 ||
        binder_version.protocol_version != BINDER_CURRENT_PROTOCOL_VERSION ||
        ioctl(binder_fd, BINDER_SET_MAX_THREADS, &binder_threads) != 0 ||
        ioctl(binder_fd, BINDER_THREAD_EXIT, 0) != 0) {
        return 155;
    }
    struct stat binder_stat;
    struct statfs binder_statfs;
    if (fstat(binder_fd, &binder_stat) != 0 ||
        !S_ISCHR(binder_stat.st_mode) ||
        fstatfs(binder_fd, &binder_statfs) != 0 ||
        binder_statfs.f_bsize != 4096 ||
        close(binder_fd) != 0) {
        return 178;
    }
    int ion_fd = open("/dev/ion", O_RDWR | O_CLOEXEC);
    struct jasper_ion_allocation_data ion_allocation = {
        .len = 8192,
        .align = 4096,
        .heap_id_mask = JASPER_ION_HEAP_SYSTEM_MASK,
        .flags = 0,
        .handle = -1,
    };
    if (ion_fd < 0 ||
        (fcntl(ion_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        ioctl(ion_fd, JASPER_ION_IOC_ALLOC, &ion_allocation) != 0 ||
        ion_allocation.handle < 0) {
        return 156;
    }
    struct jasper_ion_fd_data ion_share = {
        .handle = ion_allocation.handle,
        .fd = -1,
    };
    if (ioctl(ion_fd, JASPER_ION_IOC_SHARE, &ion_share) != 0 ||
        ion_share.fd < 0) {
        return 157;
    }
    struct stat ion_stat;
    struct statfs ion_statfs;
    if (fstat(ion_share.fd, &ion_stat) != 0 ||
        !S_ISCHR(ion_stat.st_mode) ||
        ion_stat.st_size != (off_t)ion_allocation.len ||
        fstatfs(ion_share.fd, &ion_statfs) != 0 ||
        ion_statfs.f_bsize != 4096) {
        return 179;
    }
    unsigned char *ion_first = mmap(NULL, ion_allocation.len,
                                    PROT_READ | PROT_WRITE, MAP_SHARED,
                                    ion_share.fd, 0);
    if (ion_first == MAP_FAILED) {
        return 158;
    }
    ion_first[0] = 'I';
    struct jasper_ion_handle_data ion_free = {
        .handle = ion_allocation.handle,
    };
    if (ioctl(ion_fd, JASPER_ION_IOC_SYNC, &ion_free) != 0 ||
        ioctl(ion_fd, JASPER_ION_IOC_FREE, &ion_free) != 0 ||
        ion_first[0] != 'I') {
        return 159;
    }
    struct jasper_ion_fd_data ion_import = {
        .handle = -1,
        .fd = ion_share.fd,
    };
    if (ioctl(ion_fd, JASPER_ION_IOC_IMPORT, &ion_import) != 0 ||
        ion_import.handle < 0) {
        return 160;
    }
    struct jasper_ion_fd_data ion_share_imported = {
        .handle = ion_import.handle,
        .fd = -1,
    };
    if (ioctl(ion_fd, JASPER_ION_IOC_MAP, &ion_share_imported) != 0 ||
        ion_share_imported.fd < 0) {
        return 161;
    }
    unsigned char *ion_second = mmap(NULL, ion_allocation.len,
                                     PROT_READ | PROT_WRITE, MAP_SHARED,
                                     ion_share_imported.fd, 0);
    if (ion_second == MAP_FAILED || ion_second[0] != 'I') {
        return 162;
    }
    ion_second[4096] = 'O';
    unsigned char ion_residency[2] = {0};
    if (msync(ion_second, ion_allocation.len, MS_SYNC) != 0 ||
        mincore(ion_second, ion_allocation.len, ion_residency) != 0 ||
        ion_residency[0] != 1 || ion_residency[1] != 1 ||
        munmap(ion_second, ion_allocation.len) != 0) {
        return 163;
    }
    ion_free.handle = ion_import.handle;
    if (ioctl(ion_fd, JASPER_ION_IOC_FREE, &ion_free) != 0 ||
        munmap(ion_first, ion_allocation.len) != 0 ||
        close(ion_share.fd) != 0 ||
        close(ion_share_imported.fd) != 0 ||
        close(ion_fd) != 0) {
        return 164;
    }
    int dma_heap_fd = open("/dev/dma_heap/system", O_RDWR | O_CLOEXEC);
    struct dma_heap_allocation_data dma_allocation = {
        .len = 4096,
        .fd = 0,
        .fd_flags = O_RDWR | O_CLOEXEC,
        .heap_flags = 0,
    };
    if (dma_heap_fd < 0 ||
        (fcntl(dma_heap_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        ioctl(dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &dma_allocation) != 0 ||
        dma_allocation.fd < 0 ||
        (fcntl(dma_allocation.fd, F_GETFD) & FD_CLOEXEC) == 0) {
        return 280;
    }
    struct stat dma_stat;
    if (fstat(dma_allocation.fd, &dma_stat) != 0 ||
        !S_ISREG(dma_stat.st_mode) || dma_stat.st_size != 4096) {
        return 281;
    }
    struct dma_buf_sync dma_sync = {
        .flags = DMA_BUF_SYNC_START | DMA_BUF_SYNC_RW,
    };
    if (ioctl(dma_allocation.fd, DMA_BUF_IOCTL_SYNC, &dma_sync) != 0) {
        return 282;
    }
    dma_sync.flags = DMA_BUF_SYNC_END | DMA_BUF_SYNC_RW;
    if (ioctl(dma_allocation.fd, DMA_BUF_IOCTL_SYNC, &dma_sync) != 0 ||
        ioctl(dma_allocation.fd, DMA_BUF_SET_NAME,
              (unsigned long)"jasper-dmabuf") != 0 ||
        pwrite(dma_allocation.fd, "DMA", 3, 0) != 3) {
        return 283;
    }
    unsigned char *dma_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_SHARED, dma_allocation.fd, 0);
    if (dma_map == MAP_FAILED || memcmp(dma_map, "DMA", 3) != 0) {
        return 284;
    }
    dma_map[3] = '!';
    if (msync(dma_map, 4096, MS_SYNC) != 0 ||
        munmap(dma_map, 4096) != 0) {
        return 285;
    }
    struct dma_buf_export_sync_file dma_export = {
        .flags = DMA_BUF_SYNC_WRITE,
        .fd = -1,
    };
    if (ioctl(dma_allocation.fd, DMA_BUF_IOCTL_EXPORT_SYNC_FILE,
              &dma_export) != 0 || dma_export.fd < 0) {
        return 287;
    }
    struct pollfd sync_poll = {
        .fd = dma_export.fd,
        .events = POLLIN,
    };
    if (poll(&sync_poll, 1, 0) != 1 || (sync_poll.revents & POLLIN) == 0) {
        return 288;
    }
    struct sync_file_info sync_info = {0};
    if (ioctl(dma_export.fd, SYNC_IOC_FILE_INFO, &sync_info) != 0 ||
        sync_info.status != 1 || sync_info.num_fences != 1 ||
        strcmp(sync_info.name, "dma-buf-export") != 0) {
        return 289;
    }
    struct sync_fence_info sync_fence = {0};
    sync_info.num_fences = 1;
    sync_info.sync_fence_info = (uint64_t)(uintptr_t)&sync_fence;
    if (ioctl(dma_export.fd, SYNC_IOC_FILE_INFO, &sync_info) != 0 ||
        sync_fence.status != 1 ||
        strcmp(sync_fence.driver_name, "jasper-sync-file") != 0) {
        return 290;
    }
    struct sync_merge_data sync_merge = {
        .fd2 = dma_export.fd,
        .fence = -1,
    };
    memcpy(sync_merge.name, "merged-fence", sizeof("merged-fence"));
    if (ioctl(dma_export.fd, SYNC_IOC_MERGE, &sync_merge) != 0 ||
        sync_merge.fence < 0) {
        return 291;
    }
    struct sync_set_deadline sync_deadline = {
        .deadline_ns = (uint64_t)time(NULL) * 1000000000ULL,
    };
    if (ioctl(sync_merge.fence, SYNC_IOC_SET_DEADLINE, &sync_deadline) != 0) {
        return 292;
    }
    struct dma_buf_import_sync_file dma_import = {
        .flags = DMA_BUF_SYNC_READ,
        .fd = sync_merge.fence,
    };
    if (ioctl(dma_allocation.fd, DMA_BUF_IOCTL_IMPORT_SYNC_FILE,
              &dma_import) != 0 ||
        close(sync_merge.fence) != 0 || close(dma_export.fd) != 0) {
        return 293;
    }
    struct dma_heap_allocation_data dma_invalid = {
        .len = 4095,
        .fd_flags = O_RDWR | O_CLOEXEC,
    };
    errno = 0;
    if (ioctl(dma_heap_fd, DMA_HEAP_IOCTL_ALLOC, &dma_invalid) != -1 ||
        errno != EINVAL || close(dma_allocation.fd) != 0 ||
        close(dma_heap_fd) != 0) {
        return 286;
    }
    int binder_ready[2];
    if (pipe2(binder_ready, 0) != 0) {
        return 165;
    }
    pid_t binder_server_pid = getpid();
    pid_t binder_child = fork();
    if (binder_child < 0) {
        return 166;
    }
    if (binder_child == 0) {
        close(binder_ready[1]);
        char ready = 0;
        if (read(binder_ready[0], &ready, 1) != 1 || ready != 'R') {
            _exit(167);
        }
        int client = open("/dev/binder", O_RDWR | O_CLOEXEC);
        char request_data[4] = "PING";
        struct binder_transaction_data request = {
            .target.handle = 0,
            .code = 0x1234,
            .flags = 0,
            .data_size = sizeof(request_data),
            .offsets_size = 0,
            .data.ptr.buffer = (binder_uintptr_t)request_data,
            .data.ptr.offsets = 0,
        };
        unsigned char write_buffer[4 + sizeof(request)];
        memcpy(write_buffer, &(uint32_t){BC_TRANSACTION}, 4);
        memcpy(write_buffer + 4, &request, sizeof(request));
        unsigned char read_buffer[68];
        struct binder_write_read exchange = {
            .write_size = sizeof(write_buffer),
            .write_buffer = (binder_uintptr_t)write_buffer,
            .read_size = sizeof(read_buffer),
            .read_buffer = (binder_uintptr_t)read_buffer,
        };
        if (client < 0) {
            printf("binder-client-fail stage=open errno=%d\n", errno);
            _exit(168);
        }
        int binder_ioctl_result =
            ioctl(client, BINDER_WRITE_READ, &exchange);
        if (binder_ioctl_result != 0 ||
            exchange.write_consumed != sizeof(write_buffer) ||
            exchange.read_consumed != 4 ||
            *(uint32_t *)read_buffer != BR_TRANSACTION_COMPLETE) {
            printf("binder-client-fail stage=transaction rc=%d errno=%d "
                   "write_consumed=%llu read_consumed=%llu command=%#x\n",
                   binder_ioctl_result, errno,
                   (unsigned long long)exchange.write_consumed,
                   (unsigned long long)exchange.read_consumed,
                   *(uint32_t *)read_buffer);
            _exit(168);
        }
        memset(&exchange, 0, sizeof(exchange));
        exchange.read_size = sizeof(read_buffer);
        exchange.read_buffer = (binder_uintptr_t)read_buffer;
        if (ioctl(client, BINDER_WRITE_READ, &exchange) != 0 ||
            exchange.read_consumed != 68 ||
            *(uint32_t *)read_buffer != BR_REPLY) {
            _exit(169);
        }
        struct binder_transaction_data reply;
        memcpy(&reply, read_buffer + 4, sizeof(reply));
        if (reply.code != 0x4321 || reply.sender_pid != binder_server_pid ||
            reply.data_size != sizeof(struct flat_binder_object) ||
            reply.offsets_size != sizeof(binder_size_t)) {
            _exit(170);
        }
        struct flat_binder_object returned_object;
        binder_size_t returned_offset = UINT64_MAX;
        memcpy(&returned_object, (void *)reply.data.ptr.buffer,
               sizeof(returned_object));
        memcpy(&returned_offset,
               (void *)reply.data.ptr.offsets, sizeof(returned_offset));
        if (returned_offset != 0 ||
            returned_object.hdr.type != BINDER_TYPE_HANDLE ||
            returned_object.handle == 0) {
            _exit(171);
        }
        unsigned char free_buffer[4 + sizeof(binder_uintptr_t)];
        memcpy(free_buffer, &(uint32_t){BC_FREE_BUFFER}, 4);
        binder_uintptr_t free_pointer = reply.data.ptr.buffer;
        memcpy(free_buffer + 4, &free_pointer, sizeof(free_pointer));
        struct binder_write_read cleanup = {
            .write_size = sizeof(free_buffer),
            .write_buffer = (binder_uintptr_t)free_buffer,
        };
        if (ioctl(client, BINDER_WRITE_READ, &cleanup) != 0 ||
            cleanup.write_consumed != sizeof(free_buffer)) {
            _exit(172);
        }
        char response[4] = {0};
        int binder_fd = memfd_create("binder-fd", 0);
        if (binder_fd < 0 || write(binder_fd, "FDOK", 4) != 4 ||
            lseek(binder_fd, 0, SEEK_SET) != 0) {
            _exit(173);
        }
        struct {
            struct binder_fd_object fd;
            struct flat_binder_object binder;
        } second_objects = {
            .fd = {
                .hdr.type = BINDER_TYPE_FD,
                .fd = binder_fd,
                .cookie = 0x4444,
            },
            .binder = {
                .hdr.type = BINDER_TYPE_BINDER,
                .flags = 0x7f,
                .binder = (binder_uintptr_t)(uintptr_t)&second_objects.binder,
                .cookie = 0x5555,
            },
        };
        binder_size_t second_offsets[2] = {
            0,
            sizeof(struct binder_fd_object),
        };
        struct binder_transaction_data second_request = {
            .target.handle = returned_object.handle,
            .code = 0x5678,
            .flags = 0,
            .data_size = sizeof(second_objects),
            .offsets_size = sizeof(second_offsets),
            .data.ptr.buffer = (binder_uintptr_t)&second_objects,
            .data.ptr.offsets = (binder_uintptr_t)&second_offsets,
        };
        memcpy(write_buffer, &(uint32_t){BC_TRANSACTION}, 4);
        memcpy(write_buffer + 4, &second_request, sizeof(second_request));
        memset(&exchange, 0, sizeof(exchange));
        exchange.write_size = sizeof(write_buffer);
        exchange.write_buffer = (binder_uintptr_t)write_buffer;
        exchange.read_size = sizeof(read_buffer);
        exchange.read_buffer = (binder_uintptr_t)read_buffer;
        if (ioctl(client, BINDER_WRITE_READ, &exchange) != 0 ||
            exchange.read_consumed != 4 ||
            *(uint32_t *)read_buffer != BR_TRANSACTION_COMPLETE) {
            _exit(174);
        }
        close(binder_fd);
        memset(&exchange, 0, sizeof(exchange));
        exchange.read_size = sizeof(read_buffer);
        exchange.read_buffer = (binder_uintptr_t)read_buffer;
        if (ioctl(client, BINDER_WRITE_READ, &exchange) != 0 ||
            exchange.read_consumed != 68 ||
            *(uint32_t *)read_buffer != BR_REPLY) {
            _exit(174);
        }
        memcpy(&reply, read_buffer + 4, sizeof(reply));
        if (reply.code != 0x8765 || reply.data_size != 4) {
            _exit(175);
        }
        memcpy(response, (void *)reply.data.ptr.buffer, 4);
        if (memcmp(response, "DONE", 4) != 0) {
            _exit(176);
        }
        free_pointer = reply.data.ptr.buffer;
        memcpy(free_buffer + 4, &free_pointer, sizeof(free_pointer));
        memset(&cleanup, 0, sizeof(cleanup));
        cleanup.write_size = sizeof(free_buffer);
        cleanup.write_buffer = (binder_uintptr_t)free_buffer;
        if (ioctl(client, BINDER_WRITE_READ, &cleanup) != 0 ||
            cleanup.write_consumed != sizeof(free_buffer)) {
            _exit(177);
        }
        close(client);
        close(binder_ready[0]);
        _exit(0);
    }
    close(binder_ready[0]);
    int server = open("/dev/binder", O_RDWR | O_CLOEXEC);
    unsigned char server_read[68];
    struct binder_write_read server_exchange = {
        .read_size = sizeof(server_read),
        .read_buffer = (binder_uintptr_t)server_read,
    };
    if (server < 0) {
        printf("binder-server-fail stage=open errno=%d\n", errno);
        return 173;
    }
    int context_result = ioctl(server, BINDER_SET_CONTEXT_MGR, 0);
    if (context_result != 0 || write(binder_ready[1], "R", 1) != 1) {
        printf("binder-server-fail stage=context rc=%d errno=%d\n",
               context_result, errno);
        return 173;
    }
    int server_receive_result =
        ioctl(server, BINDER_WRITE_READ, &server_exchange);
    if (server_receive_result != 0 || server_exchange.read_consumed != 68 ||
        *(uint32_t *)server_read != BR_TRANSACTION) {
        printf("binder-server-fail stage=receive rc=%d errno=%d "
               "read_consumed=%llu command=%#x\n",
               server_receive_result, errno,
               (unsigned long long)server_exchange.read_consumed,
               *(uint32_t *)server_read);
        return 173;
    }
    struct binder_transaction_data received;
    memcpy(&received, server_read + 4, sizeof(received));
    char received_data[4] = {0};
    memcpy(received_data, (void *)received.data.ptr.buffer, 4);
    if (received.code != 0x1234 || received.sender_pid != binder_child ||
        received.data_size != 4 ||
        memcmp(received_data, "PING", 4) != 0) {
        return 174;
    }
    struct flat_binder_object response_object = {
        .hdr.type = BINDER_TYPE_BINDER,
        .flags = 0x7f,
        .binder = (binder_uintptr_t)(uintptr_t)&response_object,
        .cookie = 0x7777,
    };
    binder_size_t response_offset = 0;
    struct binder_transaction_data response = {
        .code = 0x4321,
        .flags = 0,
        .data_size = sizeof(response_object),
        .offsets_size = sizeof(response_offset),
        .data.ptr.buffer = (binder_uintptr_t)&response_object,
        .data.ptr.offsets = (binder_uintptr_t)&response_offset,
    };
    unsigned char server_write[128];
    size_t server_offset = 0;
    memcpy(server_write + server_offset, &(uint32_t){BC_FREE_BUFFER}, 4);
    server_offset += 4;
    binder_uintptr_t received_pointer = received.data.ptr.buffer;
    memcpy(server_write + server_offset, &received_pointer,
           sizeof(received_pointer));
    server_offset += sizeof(received_pointer);
    memcpy(server_write + server_offset, &(uint32_t){BC_REPLY}, 4);
    server_offset += 4;
    memcpy(server_write + server_offset, &response, sizeof(response));
    server_offset += sizeof(response);
    memset(&server_exchange, 0, sizeof(server_exchange));
    server_exchange.write_size = server_offset;
    server_exchange.write_buffer = (binder_uintptr_t)server_write;
    server_exchange.read_size = 4;
    server_exchange.read_buffer = (binder_uintptr_t)server_read;
    if (ioctl(server, BINDER_WRITE_READ, &server_exchange) != 0 ||
        server_exchange.write_consumed != server_offset ||
        server_exchange.read_consumed != 4 ||
        *(uint32_t *)server_read != BR_TRANSACTION_COMPLETE) {
        return 175;
    }
    memset(&server_exchange, 0, sizeof(server_exchange));
    server_exchange.read_size = sizeof(server_read);
    server_exchange.read_buffer = (binder_uintptr_t)server_read;
    if (ioctl(server, BINDER_WRITE_READ, &server_exchange) != 0 ||
        server_exchange.read_consumed != 68 ||
        *(uint32_t *)server_read != BR_TRANSACTION) {
        return 177;
    }
    struct binder_transaction_data second_received;
    memcpy(&second_received, server_read + 4, sizeof(second_received));
    struct {
        struct binder_fd_object fd;
        struct flat_binder_object binder;
    } received_objects;
    binder_size_t received_offsets[2] = {UINT64_MAX, UINT64_MAX};
    memcpy(&received_objects, (void *)second_received.data.ptr.buffer,
           sizeof(received_objects));
    memcpy(received_offsets, (void *)second_received.data.ptr.offsets,
           sizeof(received_offsets));
    if (second_received.code != 0x5678 ||
        second_received.sender_pid != binder_child ||
        second_received.data_size != sizeof(received_objects) ||
        second_received.offsets_size != sizeof(received_offsets) ||
        received_offsets[0] != 0 ||
        received_offsets[1] != sizeof(struct binder_fd_object) ||
        received_objects.fd.hdr.type != BINDER_TYPE_FD ||
        received_objects.fd.fd < 0 ||
        received_objects.fd.cookie != 0x4444 ||
        received_objects.binder.hdr.type != BINDER_TYPE_HANDLE ||
        received_objects.binder.handle == 0 ||
        received_objects.binder.cookie != 0) {
        return 178;
    }
    char received_fd_data[4] = {0};
    if (read(received_objects.fd.fd, received_fd_data, 4) != 4 ||
        memcmp(received_fd_data, "FDOK", 4) != 0 ||
        close(received_objects.fd.fd) != 0) {
        return 179;
    }
    char done_data[4] = "DONE";
    struct binder_transaction_data done = {
        .code = 0x8765,
        .flags = 0,
        .data_size = sizeof(done_data),
        .offsets_size = 0,
        .data.ptr.buffer = (binder_uintptr_t)done_data,
    };
    server_offset = 0;
    memcpy(server_write + server_offset, &(uint32_t){BC_FREE_BUFFER}, 4);
    server_offset += 4;
    binder_uintptr_t second_pointer = second_received.data.ptr.buffer;
    memcpy(server_write + server_offset, &second_pointer,
           sizeof(second_pointer));
    server_offset += sizeof(second_pointer);
    uint32_t death_handle = received_objects.binder.handle;
    memcpy(server_write + server_offset, &(uint32_t){BC_ACQUIRE}, 4);
    server_offset += 4;
    memcpy(server_write + server_offset, &death_handle, sizeof(death_handle));
    server_offset += sizeof(death_handle);
    memcpy(server_write + server_offset, &(uint32_t){BC_RELEASE}, 4);
    server_offset += 4;
    memcpy(server_write + server_offset, &death_handle, sizeof(death_handle));
    server_offset += sizeof(death_handle);
    memcpy(server_write + server_offset,
           &(uint32_t){BC_REQUEST_DEATH_NOTIFICATION}, 4);
    server_offset += 4;
    uint64_t death_cookie = 0x9999;
    memcpy(server_write + server_offset, &death_handle, sizeof(death_handle));
    server_offset += sizeof(death_handle);
    memcpy(server_write + server_offset, &death_cookie, sizeof(death_cookie));
    server_offset += sizeof(death_cookie);
    memcpy(server_write + server_offset, &(uint32_t){BC_REPLY}, 4);
    server_offset += 4;
    memcpy(server_write + server_offset, &done, sizeof(done));
    server_offset += sizeof(done);
    memset(&server_exchange, 0, sizeof(server_exchange));
    server_exchange.write_size = server_offset;
    server_exchange.write_buffer = (binder_uintptr_t)server_write;
    server_exchange.read_size = 4;
    server_exchange.read_buffer = (binder_uintptr_t)server_read;
    if (ioctl(server, BINDER_WRITE_READ, &server_exchange) != 0 ||
        server_exchange.write_consumed != server_offset ||
        server_exchange.read_consumed != 4 ||
        *(uint32_t *)server_read != BR_TRANSACTION_COMPLETE) {
        return 179;
    }
    int binder_status = 0;
    if (waitpid(binder_child, &binder_status, 0) != binder_child ||
        !WIFEXITED(binder_status) || WEXITSTATUS(binder_status) != 0) {
        return 176;
    }
    memset(&server_exchange, 0, sizeof(server_exchange));
    server_exchange.read_size = 12;
    server_exchange.read_buffer = (binder_uintptr_t)server_read;
    if (ioctl(server, BINDER_WRITE_READ, &server_exchange) != 0 ||
        server_exchange.read_consumed != 12 ||
        *(uint32_t *)server_read != BR_DEAD_BINDER) {
        return 180;
    }
    uint64_t received_death_cookie = 0;
    memcpy(&received_death_cookie, server_read + 4, sizeof(received_death_cookie));
    if (received_death_cookie != death_cookie) {
        return 181;
    }
    unsigned char death_done[12];
    memcpy(death_done, &(uint32_t){BC_DEAD_BINDER_DONE}, 4);
    memcpy(death_done + 4, &received_death_cookie, sizeof(received_death_cookie));
    memset(&server_exchange, 0, sizeof(server_exchange));
    server_exchange.write_size = sizeof(death_done);
    server_exchange.write_buffer = (binder_uintptr_t)death_done;
    if (ioctl(server, BINDER_WRITE_READ, &server_exchange) != 0 ||
        server_exchange.write_consumed != sizeof(death_done) ||
        close(binder_ready[1]) != 0 || close(server) != 0) {
        return 182;
    }
    int poll_pipe[2];
    if (pipe2(poll_pipe, 0) != 0) {
        return 180;
    }
    pid_t poll_child = fork();
    if (poll_child < 0) {
        return 181;
    }
    if (poll_child == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&delay, NULL);
        _exit(write(poll_pipe[1], "Q", 1) == 1 ? 0 : 182);
    }
    struct pollfd poll_read = {
        .fd = poll_pipe[0],
        .events = POLLIN,
    };
    if (poll(&poll_read, 1, 300) != 1 ||
        (poll_read.revents & POLLIN) == 0 ||
        read(poll_pipe[0], blocking_bytes, 1) != 1 ||
        blocking_bytes[0] != 'Q') {
        return 183;
    }
    int poll_status = 0;
    if (waitpid(poll_child, &poll_status, 0) != poll_child ||
        !WIFEXITED(poll_status) || WEXITSTATUS(poll_status) != 0) {
        return 184;
    }
    int ppoll_pipe[2];
    if (pipe2(ppoll_pipe, 0) != 0) {
        return 187;
    }
    pid_t ppoll_child = fork();
    if (ppoll_child < 0) {
        return 188;
    }
    if (ppoll_child == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&delay, NULL);
        _exit(write(ppoll_pipe[1], "P", 1) == 1 ? 0 : 189);
    }
    struct pollfd ppoll_read = {
        .fd = ppoll_pipe[0],
        .events = POLLIN,
    };
    struct timespec ppoll_timeout = {.tv_sec = 0, .tv_nsec = 300000000};
    if (ppoll(&ppoll_read, 1, &ppoll_timeout, NULL) != 1 ||
        (ppoll_read.revents & POLLIN) == 0 ||
        read(ppoll_pipe[0], blocking_bytes, 1) != 1 ||
        blocking_bytes[0] != 'P') {
        return 190;
    }
    int ppoll_status = 0;
    if (waitpid(ppoll_child, &ppoll_status, 0) != ppoll_child ||
        !WIFEXITED(ppoll_status) || WEXITSTATUS(ppoll_status) != 0 ||
        close(ppoll_pipe[0]) != 0 || close(ppoll_pipe[1]) != 0) {
        return 191;
    }
    int select_pipe[2];
    if (pipe2(select_pipe, 0) != 0) {
        return 192;
    }
    pid_t select_child = fork();
    if (select_child < 0) {
        return 193;
    }
    if (select_child == 0) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 20000000};
        nanosleep(&delay, NULL);
        _exit(write(select_pipe[1], "S", 1) == 1 ? 0 : 194);
    }
    fd_set select_read;
    FD_ZERO(&select_read);
    FD_SET(select_pipe[0], &select_read);
    struct timeval select_timeout = {.tv_sec = 0, .tv_usec = 300000};
    if (select(select_pipe[0] + 1, &select_read, NULL, NULL,
               &select_timeout) != 1 ||
        !FD_ISSET(select_pipe[0], &select_read) ||
        read(select_pipe[0], blocking_bytes, 1) != 1 ||
        blocking_bytes[0] != 'S') {
        return 195;
    }
    int select_status = 0;
    if (waitpid(select_child, &select_status, 0) != select_child ||
        !WIFEXITED(select_status) || WEXITSTATUS(select_status) != 0 ||
        close(select_pipe[0]) != 0 || close(select_pipe[1]) != 0) {
        return 196;
    }
    int pselect_pipe[2];
    if (pipe2(pselect_pipe, 0) != 0) {
        return 197;
    }
    FD_ZERO(&select_read);
    FD_SET(pselect_pipe[0], &select_read);
    struct timespec pselect_timeout = {.tv_sec = 0, .tv_nsec = 30000000};
    if (pselect(pselect_pipe[0] + 1, &select_read, NULL, NULL,
                &pselect_timeout, NULL) != 0 ||
        FD_ISSET(pselect_pipe[0], &select_read) ||
        close(pselect_pipe[0]) != 0 || close(pselect_pipe[1]) != 0) {
        return 198;
    }
    int timeout_pipe[2];
    if (pipe2(timeout_pipe, 0) != 0) {
        return 185;
    }
    struct pollfd poll_timeout = {
        .fd = timeout_pipe[0],
        .events = POLLIN,
    };
    if (poll(&poll_timeout, 1, 30) != 0 ||
        poll_timeout.revents != 0 ||
        close(timeout_pipe[0]) != 0 || close(timeout_pipe[1]) != 0 ||
        close(poll_pipe[0]) != 0 || close(poll_pipe[1]) != 0) {
        return 186;
    }
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    struct sched_param scheduler_parameter = {.sched_priority = 0};
    struct sched_param scheduler_current = {.sched_priority = -1};
    if (sched_setscheduler(0, SCHED_OTHER, &scheduler_parameter) != 0 ||
        sched_getparam(0, &scheduler_current) != 0 ||
        scheduler_current.sched_priority != 0) {
        return 215;
    }
    errno = 0;
    if (sched_setscheduler(0, SCHED_FIFO, &scheduler_parameter) != -1 ||
        errno != EPERM) {
        return 216;
    }
    if (sched_setaffinity(0, sizeof(cpus), &cpus) != 0) {
        return 214;
    }
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus) != 0 ||
        CPU_COUNT(&cpus) < 1 || !CPU_ISSET(0, &cpus)) {
        return 11;
    }
    errno = 0;
    if (sched_getaffinity(0, 1, &cpus) != -1 || errno != EINVAL) {
        return 12;
    }
    unsigned cpu = UINT32_MAX;
    unsigned node = UINT32_MAX;
    if (syscall(SYS_getcpu, &cpu, &node, NULL) != 0 ||
        cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, &cpus) || node != 0) {
        return 13;
    }
    errno = 0;
    if (syscall(SYS_getcpu, (void *)1, NULL, NULL) != -1 || errno != EFAULT) {
        return 14;
    }
    char executable[128];
    ssize_t executable_len = readlinkat(AT_FDCWD, "/proc/self/exe",
                                       executable, sizeof(executable) - 1);
    if (executable_len <= 0 ||
        (size_t)executable_len >= sizeof(executable) - 1) {
        return 15;
    }
    executable[executable_len] = '\0';
    if (strcmp(executable, "/usr/bin/jasper-getppid") != 0) {
        return 16;
    }
    if (syscall(SYS_faccessat2, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6", R_OK, 0) != 0) {
        return 204;
    }
    errno = 0;
    if (syscall(SYS_faccessat2, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6", W_OK, 0) != -1 ||
        errno != EACCES) {
        return 205;
    }
    errno = 0;
    if (syscall(SYS_faccessat2, AT_FDCWD, "/missing-access", F_OK, 0) != -1 ||
        errno != ENOENT) {
        return 206;
    }
    struct stat legacy_stat;
    const char *legacy_libc = "/usr/lib/x86_64-linux-gnu/libc.so.6";
    if (syscall(SYS_stat, legacy_libc, &legacy_stat) != 0 ||
        !S_ISREG(legacy_stat.st_mode) || legacy_stat.st_size <= 0 ||
        syscall(SYS_lstat, legacy_libc, &legacy_stat) != 0 ||
        !S_ISREG(legacy_stat.st_mode)) {
        return 263;
    }
    errno = 0;
    if (syscall(SYS_stat, "/missing-legacy-stat", &legacy_stat) != -1 ||
        errno != ENOENT || syscall(SYS_lstat, "/missing-legacy-stat",
                                   &legacy_stat) != -1 ||
        errno != ENOENT) {
        return 264;
    }
    errno = 0;
    if (syscall(SYS_chmod, legacy_libc, 0600) != -1 || errno != EROFS ||
        syscall(SYS_chown, legacy_libc, 0, 0) != -1 || errno != EROFS ||
        syscall(SYS_futimesat, AT_FDCWD, legacy_libc, NULL) != -1 ||
        errno != EROFS) {
        return 265;
    }
    struct rlimit legacy_limit;
    if (syscall(SYS_getrlimit, RLIMIT_NOFILE, &legacy_limit) != 0 ||
        legacy_limit.rlim_cur != 64 || legacy_limit.rlim_max != 64) {
        return 266;
    }
    errno = 0;
    if (syscall(SYS_setrlimit, RLIMIT_NOFILE, &legacy_limit) != -1 ||
        errno != EPERM) {
        return 267;
    }
    errno = 0;
    long empty_access =
        syscall(SYS_faccessat2, fd, "", R_OK, AT_EMPTY_PATH);
    if (empty_access != 0) {
        printf("faccessat2-empty-fail fd=%d result=%ld errno=%d\n",
               fd, empty_access, errno);
        return 207;
    }
    errno = 0;
    if (fchmod(fd, 0600) != -1 || errno != EROFS) {
        return 218;
    }
    errno = 0;
    int fchmodat_result =
        fchmodat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                 0600, 0);
    int fchmodat_errno = errno;
    if (fchmodat_result != -1 || fchmodat_errno != EROFS) {
        printf("fchmodat-fail result=%d errno=%d\n",
               fchmodat_result, fchmodat_errno);
        return 219;
    }
    errno = 0;
    if (fchmodat(AT_FDCWD, "/missing-chmod", 0600, 0) != -1 ||
        errno != ENOENT) {
        return 220;
    }
    errno = 0;
    if (fchown(fd, 0, 0) != -1 || errno != EROFS) {
        return 221;
    }
    errno = 0;
    if (fchownat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                 0, 0, 0) != -1 ||
        errno != EROFS) {
        return 222;
    }
    errno = 0;
    if (fchownat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                 123, 0, 0) != -1 ||
        errno != EPERM) {
        return 224;
    }
    errno = 0;
    if (lchown("/usr/lib/x86_64-linux-gnu/libc.so.6", 0, 0) != -1 ||
        errno != EROFS) {
        return 235;
    }
    errno = 0;
    if (ftruncate(fd, 0) != -1 || errno != EROFS) {
        return 232;
    }
    errno = 0;
    int truncate_result =
        truncate("/usr/lib/x86_64-linux-gnu/libc.so.6", 0);
    int truncate_errno = errno;
    if (truncate_result != -1 || truncate_errno != EROFS) {
        printf("truncate-fail result=%d errno=%d\n",
               truncate_result, truncate_errno);
        return 233;
    }
    errno = 0;
    if (truncate("/missing-truncate", 0) != -1 || errno != ENOENT) {
        return 234;
    }
    errno = 0;
    if (utime("/usr/lib/x86_64-linux-gnu/libc.so.6", NULL) != -1 ||
        errno != EROFS) {
        return 239;
    }
    errno = 0;
    if (utimes("/usr/lib/x86_64-linux-gnu/libc.so.6", NULL) != -1 ||
        errno != EROFS) {
        return 240;
    }
    errno = 0;
    if (utimensat(AT_FDCWD, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                  NULL, 0) != -1 ||
        errno != EROFS) {
        return 242;
    }
    errno = 0;
    if (utimensat(AT_FDCWD, "/missing-time", NULL, 0) != -1 ||
        errno != ENOENT) {
        return 243;
    }
    errno = 0;
    if (readlinkat(AT_FDCWD, "/not-in-compat-root",
                   executable, sizeof(executable)) != -1 || errno != ENOENT) {
        return 17;
    }
    struct sysinfo info;
    if (sysinfo(&info) != 0 || info.uptime < 0 || info.totalram == 0 ||
        info.freeram == 0 || info.freeram > info.totalram || info.mem_unit == 0 ||
        info.procs == 0 || info.totalswap != 0 || info.freeswap != 0) {
        return 18;
    }
    errno = 0;
    if (syscall(SYS_sysinfo, (void *)1) != -1 || errno != EFAULT) {
        return 19;
    }
    struct timespec resolution;
    if (clock_getres(CLOCK_MONOTONIC, &resolution) != 0 ||
        resolution.tv_sec < 0 || resolution.tv_nsec <= 0 ||
        resolution.tv_nsec >= 1000000000L) {
        return 20;
    }
    struct timespec realtime_resolution;
    struct timespec realtime_now;
    struct timeval realtime_value;
    if (clock_getres(CLOCK_REALTIME, &realtime_resolution) != 0 ||
        realtime_resolution.tv_sec != 1 ||
        realtime_resolution.tv_nsec != 0 ||
        clock_gettime(CLOCK_REALTIME, &realtime_now) != 0 ||
        gettimeofday(&realtime_value, NULL) != 0) {
        return 21;
    }
    long realtime_delta =
        (long)(realtime_value.tv_sec - realtime_now.tv_sec);
    if (realtime_now.tv_sec < 1600000000LL ||
        realtime_now.tv_sec > 4102444800LL ||
        realtime_delta < -2 || realtime_delta > 2) {
        return 21;
    }
    unsigned char random_bytes[32];
    memset(random_bytes, 0, sizeof(random_bytes));
    if (getrandom(random_bytes, sizeof(random_bytes), 0) !=
        (ssize_t)sizeof(random_bytes)) {
        return 22;
    }
    int random_nonzero = 0;
    for (unsigned i = 0; i < sizeof(random_bytes); i++) {
        random_nonzero |= random_bytes[i] != 0;
    }
    errno = 0;
    if (!random_nonzero ||
        getrandom((void *)1, 8, 0) != -1 || errno != EFAULT) {
        return 23;
    }
    printf("jasper-random-ok bytes=%u\n", (unsigned)sizeof(random_bytes));
    struct timespec before_sleep;
    struct timespec after_sleep;
    const struct timespec short_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (clock_gettime(CLOCK_MONOTONIC, &before_sleep) != 0) {
        printf("jasper-time-fail stage=before errno=%d\n", errno);
        return 24;
    }
    if (nanosleep(&short_delay, NULL) != 0) {
        printf("jasper-time-fail stage=nanosleep errno=%d\n", errno);
        return 24;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after_sleep) != 0) {
        printf("jasper-time-fail stage=after errno=%d\n", errno);
        return 24;
    }
    long long relative_elapsed =
        (after_sleep.tv_sec - before_sleep.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - before_sleep.tv_nsec);
    if (relative_elapsed < 10000000LL) {
        return 25;
    }
    struct timespec absolute_deadline = after_sleep;
    absolute_deadline.tv_nsec += 10000000L;
    if (absolute_deadline.tv_nsec >= 1000000000L) {
        absolute_deadline.tv_sec += 1;
        absolute_deadline.tv_nsec -= 1000000000L;
    }
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                        &absolute_deadline, NULL) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &after_sleep) != 0) {
        return 26;
    }
    long long absolute_elapsed =
        (after_sleep.tv_sec - absolute_deadline.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - absolute_deadline.tv_nsec);
    if (absolute_elapsed < 0) {
        return 27;
    }
    errno = 0;
    if (nanosleep((const struct timespec *)1, NULL) != -1 || errno != EFAULT) {
        return 28;
    }
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_PROCESS_CPUTIME_ID, 0,
                &short_delay, NULL) != -1 || errno != EINVAL) {
        return 29;
    }
    DIR *root = opendir("/");
    if (root == NULL) {
        return 30;
    }
    int root_fd = dirfd(root);
    errno = 0;
    if (syscall(SYS_getdents64, root_fd, (void *)1, 256) != -1 ||
        errno != EFAULT) {
        return 31;
    }
    int saw_usr = 0;
    unsigned root_entries = 0;
    char first_root_name[256] = {0};
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(root)) != NULL) {
        if (root_entries == 0) {
            snprintf(first_root_name, sizeof(first_root_name), "%s",
                     entry->d_name);
        }
        root_entries++;
        saw_usr |= strcmp(entry->d_name, "usr") == 0;
    }
    if (errno != 0 || root_entries < 4 || !saw_usr ||
        first_root_name[0] == '\0') {
        return 32;
    }
    rewinddir(root);
    entry = readdir(root);
    if (entry == NULL || strcmp(entry->d_name, first_root_name) != 0) {
        return 33;
    }
    int usr_fd = openat(root_fd, "usr", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (usr_fd < 0) {
        return 34;
    }
    struct stat usr_stat;
    if (fstat(usr_fd, &usr_stat) != 0 || !S_ISDIR(usr_stat.st_mode)) {
        return 35;
    }
    if (fstatat(root_fd, "usr", &usr_stat, 0) != 0 ||
        !S_ISDIR(usr_stat.st_mode)) {
        return 36;
    }
    struct statx usr_statx;
    if (statx(root_fd, "usr", AT_STATX_SYNC_AS_STAT, STATX_TYPE,
              &usr_statx) != 0 || !S_ISDIR(usr_statx.stx_mode)) {
        return 37;
    }
    errno = 0;
    if (statx(AT_FDCWD, "/", AT_STATX_SYNC_AS_STAT, STATX_TYPE,
              (struct statx *)1) != -1 || errno != EFAULT) {
        return 38;
    }
    char cwd_buffer[32];
    if (chdir("/usr") != 0 ||
        getcwd(cwd_buffer, sizeof(cwd_buffer)) == NULL ||
        strcmp(cwd_buffer, "/usr") != 0) {
        return 39;
    }
    int relative_lib = openat(AT_FDCWD, "lib",
                              O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (relative_lib < 0) {
        return 40;
    }
    close(relative_lib);
    if (fchdir(root_fd) != 0 ||
        getcwd(cwd_buffer, sizeof(cwd_buffer)) == NULL ||
        strcmp(cwd_buffer, "/") != 0) {
        return 41;
    }
    close(usr_fd);
    if (closedir(root) != 0) {
        return 42;
    }
    DIR *directory = opendir("/usr/lib/x86_64-linux-gnu");
    if (directory == NULL) {
        return 43;
    }
    unsigned library_mask = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "libc.so.6") == 0) library_mask |= 1u << 0;
        if (strcmp(entry->d_name, "libsystemd.so.0") == 0) library_mask |= 1u << 1;
        if (strcmp(entry->d_name, "libselinux.so.1") == 0) library_mask |= 1u << 2;
        if (strcmp(entry->d_name, "libgcc_s.so.1") == 0) library_mask |= 1u << 3;
        if (strcmp(entry->d_name, "libm.so.6") == 0) library_mask |= 1u << 4;
        if (strcmp(entry->d_name, "libpcre2-8.so.0") == 0) library_mask |= 1u << 5;
    }
    if (closedir(directory) != 0 || library_mask != 0x3fu) {
        return 44;
    }
    errno = 0;
    directory = opendir("/usr/lib/x86_64-linux-gnu/libc.so.6");
    if (directory != NULL || errno != ENOTDIR) {
        if (directory != NULL) closedir(directory);
        return 45;
    }
    struct statfs compatibility_fs;
    if (fstatfs(fd, &compatibility_fs) != 0 ||
        compatibility_fs.f_type != 0xef53 ||
        compatibility_fs.f_bsize != 4096) {
        return 44;
    }
    directory = opendir("/usr/bin");
    if (directory == NULL) {
        return 47;
    }
    unsigned executable_mask = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "basename") == 0) executable_mask |= 1u << 0;
        if (strcmp(entry->d_name, "find") == 0) executable_mask |= 1u << 1;
        if (strcmp(entry->d_name, "ls") == 0) executable_mask |= 1u << 2;
        if (strcmp(entry->d_name, "wc") == 0) executable_mask |= 1u << 3;
    }
    if (closedir(directory) != 0 || executable_mask != 0x0fu) {
        return 48;
    }
    errno = 0;
    int executable_fd = open("/usr/bin/ls", O_RDONLY | O_CLOEXEC);
    if (executable_fd != -1 || errno != EACCES) {
        if (executable_fd >= 0) close(executable_fd);
        return 49;
    }
    errno = 0;
    executable_fd = open("/usr/bin/ls", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (executable_fd != -1 || errno != ENOTDIR) {
        if (executable_fd >= 0) close(executable_fd);
        return 50;
    }
    errno = 0;
    if (chdir("/usr/bin/ls") != -1 || errno != ENOTDIR) {
        return 51;
    }
    struct stat executable_stat;
    if (stat("/usr/bin/ls", &executable_stat) != 0 ||
        !S_ISREG(executable_stat.st_mode)) {
        return 52;
    }
    if ((executable_stat.st_mode & 0111) != 0111 ||
        executable_stat.st_nlink != 1 || executable_stat.st_size != 0) {
        return 53;
    }
    struct statx executable_statx;
    if (statx(AT_FDCWD, "/usr/bin/ls", AT_STATX_SYNC_AS_STAT,
              STATX_BASIC_STATS, &executable_statx) != 0 ||
        !S_ISREG(executable_statx.stx_mode) ||
        (executable_statx.stx_mode & 0111) != 0111 ||
        executable_statx.stx_nlink != 1 ||
        executable_statx.stx_size != 0) {
        return 54;
    }
    errno = 0;
    if (ioctl(STDOUT_FILENO, 0x802c542aUL, NULL) != -1 || errno != ENOTTY) {
        return 45;
    }
    if (sched_getscheduler(0) != SCHED_OTHER) {
        return 46;
    }
    pid_t fork_parent_pid = getpid();
    volatile int fork_private = 0x1234;
    pid_t first_child = fork();
    if (first_child < 0) {
        printf("jasper-fork-fail stage=first errno=%d\n", errno);
        return 59;
    }
    if (first_child == 0) {
        _exit(6);
    }
    pid_t child = fork();
    if (child < 0) {
        printf("jasper-fork-fail errno=%d\n", errno);
        return 55;
    }
    if (child == 0) {
        if (getppid() != fork_parent_pid) {
            _exit(8);
        }
        fork_private = 0x5678;
        _exit(7);
    }
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 7) {
        return 56;
    }
    if (fork_private != 0x1234) {
        return 57;
    }
    child_status = 0;
    if (waitpid(first_child, &child_status, 0) != first_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 6) {
        return 60;
    }
    errno = 0;
    if (waitpid(child, &child_status, 0) != -1 || errno != ECHILD) {
        return 58;
    }
    pid_t any_a = fork();
    if (any_a < 0) {
        return 62;
    }
    if (any_a == 0) {
        _exit(9);
    }
    pid_t any_b = fork();
    if (any_b < 0) {
        return 63;
    }
    if (any_b == 0) {
        _exit(10);
    }
    int saw_nine = 0;
    int saw_ten = 0;
    for (int i = 0; i < 2; i++) {
        child_status = 0;
        pid_t reaped = waitpid(-1, &child_status, 0);
        if (reaped != any_a && reaped != any_b) {
            return 64;
        }
        if (!WIFEXITED(child_status)) {
            return 65;
        }
        int code = WEXITSTATUS(child_status);
        saw_nine |= code == 9;
        saw_ten |= code == 10;
    }
    if (!saw_nine || !saw_ten) {
        return 66;
    }
    errno = 0;
    if (waitpid(-1, &child_status, WNOHANG) != -1 || errno != ECHILD) {
        return 67;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        return 81;
    }
    pid_t ofd_child = fork();
    if (ofd_child < 0) {
        return 82;
    }
    if (ofd_child == 0) {
        _exit(lseek(fd, 12, SEEK_SET) == 12 ? 0 : 83);
    }
    child_status = 0;
    if (waitpid(ofd_child, &child_status, 0) != ofd_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        lseek(fd, 0, SEEK_CUR) != 12) {
        return 84;
    }
    if (lseek(fd, 0, SEEK_SET) != 0) {
        return 85;
    }
    pid_t vfork_child = vfork();
    if (vfork_child < 0) {
        return 68;
    }
    if (vfork_child == 0) {
        char *vfork_argv[] = {
            "/usr/bin/printf",
            "jasper-vfork-%s\n",
            "ok",
            NULL,
        };
        char *vfork_envp[] = {NULL};
        execve(vfork_argv[0], vfork_argv, vfork_envp);
        printf("jasper-vfork-exec-fail errno=%d\n", errno);
        fflush(stdout);
        _exit(69);
    }
    child_status = 0;
    if (waitpid(vfork_child, &child_status, 0) != vfork_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        return 70;
    }
    uid_t real_uid = (uid_t)-1;
    uid_t effective_uid = (uid_t)-1;
    uid_t saved_uid = (uid_t)-1;
    gid_t real_gid = (gid_t)-1;
    gid_t effective_gid = (gid_t)-1;
    gid_t saved_gid = (gid_t)-1;
    pid_t process_id = getpid();
    if (getpgrp() != process_id || getpgid(0) != process_id ||
        getsid(0) != process_id || setsid() != process_id ||
        getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        real_uid != 0 || effective_uid != 0 || saved_uid != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_gid != 0 || effective_gid != 0 || saved_gid != 0) {
        return 217;
    }
    close(fd);
    printf("jasper-ppid=%d lseek=%lld affinity=%d cpu=%u node=%u uptime=%lld totalram=%llu freeram=%llu procs=%u exe=%s resolution_ns=%ld sleep_ns=%lld wall=%lld dirent=6 exec_meta=true fork=true\n",
           (int)parent, (long long)end, CPU_COUNT(&cpus), cpu, node,
           (long long)info.uptime, (unsigned long long)info.totalram,
           (unsigned long long)info.freeram, (unsigned)info.procs, executable,
           resolution.tv_nsec, relative_elapsed, (long long)realtime_now.tv_sec);
    printf("jasper-exec-before pid=%d ppid=%d\n", getpid(), getppid());
    fflush(stdout);
    char *exec_argv[] = {"/usr/bin/jasper-getppid", NULL};
    char *exec_envp[] = {"JASPER_EXEC_CHILD=1", NULL};
    execve(exec_argv[0], exec_argv, exec_envp);
    printf("jasper-exec-fail errno=%d\n", errno);
    return 61;
}
