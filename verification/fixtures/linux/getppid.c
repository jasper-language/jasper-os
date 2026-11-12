// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/android/binder.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
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
    if (msync(shared, ashmem_size, MS_SYNC) != 0) {
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
    if (msync(ion_second, ion_allocation.len, MS_SYNC) != 0 ||
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
            reply.data_size != 4) {
            _exit(170);
        }
        char response[4] = {0};
        memcpy(response, (void *)reply.data.ptr.buffer, 4);
        if (memcmp(response, "PONG", 4) != 0) {
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
    char response_data[4] = "PONG";
    struct binder_transaction_data response = {
        .code = 0x4321,
        .flags = 0,
        .data_size = sizeof(response_data),
        .offsets_size = 0,
        .data.ptr.buffer = (binder_uintptr_t)response_data,
    };
    unsigned char server_write[12 + 4 + sizeof(response)];
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
    int binder_status = 0;
    if (waitpid(binder_child, &binder_status, 0) != binder_child ||
        !WIFEXITED(binder_status) || WEXITSTATUS(binder_status) != 0 ||
        close(binder_ready[1]) != 0 || close(server) != 0) {
        return 176;
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
