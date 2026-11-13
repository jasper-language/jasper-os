// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <asm/prctl.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/android/binder.h>
#include <linux/aio_abi.h>
#include <linux/capability.h>
#include <linux/dma-buf.h>
#include <linux/dma-heap.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/io_uring.h>
#include <linux/ioprio.h>
#include <linux/kcmp.h>
#include <linux/landlock.h>
#include <linux/lsm.h>
#include <linux/membarrier.h>
#include <linux/mount.h>
#include <linux/nsfs.h>
#include <linux/mman.h>
#include <linux/sched/types.h>
#include <linux/seccomp.h>
#include <linux/sync_file.h>
#include <limits.h>
#include <mqueue.h>
#include <linux/mempolicy.h>
#include <pthread.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/inotify.h>
#include <sys/ipc.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/timerfd.h>
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

#ifndef SYS_uprobe
#define SYS_uprobe 336
#endif
#ifndef SYS_listns
#define SYS_listns 470
#endif
#ifndef SYS_rseq_slice_yield
#define SYS_rseq_slice_yield 471
#endif
#ifndef SYS_futex_wake
#define SYS_futex_wake 454
#endif
#ifndef SYS_futex_wait
#define SYS_futex_wait 455
#endif
#ifndef SYS_futex_requeue
#define SYS_futex_requeue 456
#endif
#ifndef SYS_futex_waitv
#define SYS_futex_waitv 449
#endif

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

struct legacy_dirent_probe {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[];
};

struct robust_list_probe {
    void *list;
    long futex_offset;
    void *list_op_pending;
} __attribute__((aligned(8)));

struct jasper_xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

struct futex2_waitv_probe {
    uint64_t value;
    uint64_t address;
    uint32_t flags;
    uint32_t reserved;
};

static void signal_noop(int signal) {
    (void)signal;
}

static volatile sig_atomic_t posix_timer_signals;
static volatile sig_atomic_t interval_timer_signals;
static volatile sig_atomic_t sigsuspend_signals;
static volatile sig_atomic_t mq_notification_signals;
static volatile sig_atomic_t mq_notification_pid;
static volatile sig_atomic_t mq_notification_uid;
static volatile sig_atomic_t mq_notification_code;
static volatile sig_atomic_t mq_notification_value;
static atomic_int landlock_worker_stage;
static atomic_int landlock_worker_first_done;
static atomic_int landlock_worker_second_done;
static atomic_int landlock_worker_first_ok;
static atomic_int landlock_worker_second_ok;
static volatile sig_atomic_t pdeath_done_fd = -1;

static void pdeath_signal_handler(int signal) {
    if (signal == SIGTERM && pdeath_done_fd >= 0) {
        char done = 'D';
        (void)write((int)pdeath_done_fd, &done, 1);
    }
    _exit(0);
}

static int landlock_worker_open(int expect_usr, int expect_lib) {
    int usr = open("/usr/lib/x86_64-linux-gnu/libc.so.6",
                   O_RDONLY | O_CLOEXEC);
    errno = 0;
    int lib = open("/lib/x86_64-linux-gnu/libc.so.6",
                   O_RDONLY | O_CLOEXEC);
    int lib_errno = errno;
    int ok = (expect_usr ? usr >= 0 : usr == -1) &&
             (expect_lib == 0 ? lib >= 0 : lib == -1 &&
              lib_errno == EACCES);
    if (usr >= 0) {
        close(usr);
    }
    if (lib >= 0) {
        close(lib);
    }
    return ok;
}

static void *landlock_worker(void *argument) {
    (void)argument;
    while (atomic_load_explicit(&landlock_worker_stage,
                                memory_order_acquire) == 0) {
        sched_yield();
    }
    atomic_store_explicit(&landlock_worker_first_ok,
                          landlock_worker_open(1, 0),
                          memory_order_release);
    atomic_store_explicit(&landlock_worker_first_done, 1,
                          memory_order_release);
    while (atomic_load_explicit(&landlock_worker_stage,
                                memory_order_acquire) == 1) {
        sched_yield();
    }
    atomic_store_explicit(&landlock_worker_second_ok,
                          landlock_worker_open(1, 1),
                          memory_order_release);
    atomic_store_explicit(&landlock_worker_second_done, 1,
                          memory_order_release);
    return NULL;
}

static void mq_notification_handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal == SIGUSR1) {
        mq_notification_signals++;
        if (info != NULL) {
            mq_notification_pid = info->si_pid;
            mq_notification_uid = info->si_uid;
            mq_notification_code = info->si_code;
            mq_notification_value = info->si_value.sival_int;
        }
    }
}

static void posix_timer_signal_handler(int signal) {
    if (signal == SIGUSR1) {
        posix_timer_signals++;
    }
}

static void interval_timer_signal_handler(int signal) {
    if (signal == SIGALRM) {
        interval_timer_signals++;
    }
}

static void sigsuspend_signal_handler(int signal) {
    if (signal == SIGUSR1) {
        sigsuspend_signals++;
    }
}

static int wait_for_interval_signals(int expected) {
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        return -1;
    }
    deadline.tv_nsec += 500000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    const struct timespec delay = {.tv_sec = 0, .tv_nsec = 5000000L};
    struct timespec now;
    do {
        if (interval_timer_signals >= expected) {
            return 0;
        }
        struct timespec remaining = delay;
        nanosleep(&remaining, NULL);
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            return -1;
        }
    } while (now.tv_sec < deadline.tv_sec ||
             (now.tv_sec == deadline.tv_sec &&
              now.tv_nsec < deadline.tv_nsec));
    return interval_timer_signals >= expected ? 0 : -1;
}

static uint32_t futex_word;
static uint32_t futex2_word;
static uint32_t futex2_destination;
static atomic_int futex_started;
static atomic_int futex_finished;
static uint32_t futex_requeue_source;
static uint32_t futex_requeue_target;
static atomic_int futex_requeue_started;
static atomic_int futex_requeue_finished;
static atomic_int futex2_started;
static atomic_int futex2_finished;

struct futex_thread_arg {
    uint32_t bitset;
};

struct prctl_thread_result {
    int set_result;
    int get_result;
    char inherited[16];
    char changed[16];
};

static void *prctl_name_worker(void *argument) {
    struct prctl_thread_result *result = argument;
    result->get_result = prctl(PR_GET_NAME, result->inherited, 0, 0, 0);
    result->set_result = prctl(PR_SET_NAME, "worker-thread", 0, 0, 0);
    if (result->get_result == 0 &&
        prctl(PR_GET_NAME, result->changed, 0, 0, 0) != 0) {
        result->get_result = -1;
    }
    return NULL;
}

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

static void *futex_requeue_waiter(void *argument) {
    (void)argument;
    struct timespec deadline;
    if (clock_gettime(CLOCK_MONOTONIC, &deadline) != 0) {
        return (void *)(intptr_t)-1000;
    }
    deadline.tv_sec += 1;
    atomic_fetch_add_explicit(&futex_requeue_started, 1, memory_order_release);
    long result = syscall(SYS_futex, &futex_requeue_source,
                          FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0,
                          &deadline, NULL, 0);
    atomic_fetch_add_explicit(&futex_requeue_finished, 1, memory_order_release);
    return (void *)(intptr_t)result;
}

static void *futex2_waiter(void *argument) {
    (void)argument;
    atomic_store_explicit(&futex2_started, 1, memory_order_release);
    long result = syscall(
        SYS_futex_wait, &futex2_word, 0U, UINT32_MAX,
        FUTEX2_SIZE_U32 | FUTEX2_PRIVATE, NULL, CLOCK_MONOTONIC);
    atomic_store_explicit(&futex2_finished, 1, memory_order_release);
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
    sigset_t signalfd_saved_mask;
    sigset_t signalfd_mask;
    sigemptyset(&signalfd_mask);
    sigaddset(&signalfd_mask, SIGUSR1);
    sigaddset(&signalfd_mask, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &signalfd_mask, &signalfd_saved_mask) != 0) {
        return 370;
    }
    sigemptyset(&signalfd_mask);
    sigaddset(&signalfd_mask, SIGUSR1);
    int signalfd_fd = signalfd(-1, &signalfd_mask,
                               SFD_CLOEXEC | SFD_NONBLOCK);
    if (signalfd_fd < 0 ||
        (fcntl(signalfd_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        kill(getpid(), SIGUSR1) != 0) {
        return 371;
    }
    struct pollfd signalfd_poll = {
        .fd = signalfd_fd,
        .events = POLLIN,
    };
    struct signalfd_siginfo signal_info = {0};
    if (poll(&signalfd_poll, 1, 1000) != 1 ||
        (signalfd_poll.revents & POLLIN) == 0 ||
        read(signalfd_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1 ||
        signal_info.ssi_code != SI_USER ||
        signal_info.ssi_pid != (uint32_t)getpid()) {
        return 372;
    }
    errno = 0;
    if (read(signalfd_fd, &signal_info, sizeof(signal_info)) != -1 ||
        errno != EAGAIN) {
        return 373;
    }
    int signalfd_epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event signalfd_interest = {
        .events = EPOLLIN,
        .data.u64 = 0x5349474e4644ULL,
    };
    struct epoll_event signalfd_ready = {0};
    if (signalfd_epfd < 0 ||
        epoll_ctl(signalfd_epfd, EPOLL_CTL_ADD, signalfd_fd,
                  &signalfd_interest) != 0 ||
        kill(getpid(), SIGUSR1) != 0 ||
        epoll_wait(signalfd_epfd, &signalfd_ready, 1, 1000) != 1 ||
        (signalfd_ready.events & EPOLLIN) == 0 ||
        signalfd_ready.data.u64 != 0x5349474e4644ULL) {
        return 374;
    }
    memset(&signal_info, 0, sizeof(signal_info));
    if (read(signalfd_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1) {
        return 375;
    }
    sigemptyset(&signalfd_mask);
    sigaddset(&signalfd_mask, SIGUSR2);
    if (syscall(SYS_signalfd4, signalfd_fd, &signalfd_mask,
                8, SFD_NONBLOCK) != signalfd_fd) {
        return 376;
    }
    pid_t signalfd_child = fork();
    if (signalfd_child < 0) {
        return 377;
    }
    if (signalfd_child == 0) {
        _exit(kill(getppid(), SIGUSR2) == 0 ? 0 : 1);
    }
    int signalfd_child_status = 0;
    if (waitpid(signalfd_child, &signalfd_child_status, 0) != signalfd_child ||
        !WIFEXITED(signalfd_child_status) ||
        WEXITSTATUS(signalfd_child_status) != 0 ||
        poll(&signalfd_poll, 1, 1000) != 1) {
        return 378;
    }
    memset(&signal_info, 0, sizeof(signal_info));
    if (read(signalfd_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR2 ||
        signal_info.ssi_code != SI_USER ||
        signal_info.ssi_pid != (uint32_t)signalfd_child) {
        return 379;
    }
    sigemptyset(&signalfd_mask);
    sigaddset(&signalfd_mask, SIGUSR1);
    if (syscall(SYS_signalfd4, signalfd_fd, &signalfd_mask,
                8, SFD_NONBLOCK) != signalfd_fd ||
        syscall(SYS_tgkill, getpid(), gettid(), SIGUSR1) != 0 ||
        poll(&signalfd_poll, 1, 1000) != 1) {
        return 380;
    }
    memset(&signal_info, 0, sizeof(signal_info));
    if (read(signalfd_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1 ||
        signal_info.ssi_code != SI_TKILL ||
        signal_info.ssi_pid != (uint32_t)getpid()) {
        return 381;
    }
    int signalfd_socket[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, signalfd_socket) != 0) {
        return 382;
    }
    char signalfd_control[CMSG_SPACE(sizeof(int))];
    memset(signalfd_control, 0, sizeof(signalfd_control));
    char signalfd_byte = 'G';
    struct iovec signalfd_iov = {
        .iov_base = &signalfd_byte,
        .iov_len = 1,
    };
    struct msghdr signalfd_send = {
        .msg_iov = &signalfd_iov,
        .msg_iovlen = 1,
        .msg_control = signalfd_control,
        .msg_controllen = sizeof(signalfd_control),
    };
    struct cmsghdr *signalfd_cmsg = CMSG_FIRSTHDR(&signalfd_send);
    signalfd_cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    signalfd_cmsg->cmsg_level = SOL_SOCKET;
    signalfd_cmsg->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(signalfd_cmsg), &signalfd_fd, sizeof(int));
    if (sendmsg(signalfd_socket[0], &signalfd_send, MSG_NOSIGNAL) != 1) {
        return 383;
    }
    memset(signalfd_control, 0, sizeof(signalfd_control));
    char signalfd_received_byte = 0;
    struct iovec signalfd_receive_iov = {
        .iov_base = &signalfd_received_byte,
        .iov_len = 1,
    };
    struct msghdr signalfd_receive = {
        .msg_iov = &signalfd_receive_iov,
        .msg_iovlen = 1,
        .msg_control = signalfd_control,
        .msg_controllen = sizeof(signalfd_control),
    };
    if (recvmsg(signalfd_socket[1], &signalfd_receive,
                MSG_CMSG_CLOEXEC) != 1 ||
        signalfd_received_byte != 'G') {
        return 384;
    }
    struct cmsghdr *signalfd_received_cmsg = CMSG_FIRSTHDR(&signalfd_receive);
    int signalfd_received = -1;
    if (!signalfd_received_cmsg ||
        signalfd_received_cmsg->cmsg_type != SCM_RIGHTS) {
        return 385;
    }
    memcpy(&signalfd_received, CMSG_DATA(signalfd_received_cmsg),
           sizeof(signalfd_received));
    if (signalfd_received < 0 ||
        (fcntl(signalfd_received, F_GETFD) & FD_CLOEXEC) == 0 ||
        kill(getpid(), SIGUSR1) != 0 ||
        read(signalfd_received, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1) {
        return 386;
    }
    int blocking_signalfd = signalfd(-1, &signalfd_mask, SFD_CLOEXEC);
    pid_t blocking_signalfd_child = fork();
    if (blocking_signalfd < 0 || blocking_signalfd_child < 0) {
        return 390;
    }
    if (blocking_signalfd_child == 0) {
        struct timespec signalfd_delay = {
            .tv_sec = 0,
            .tv_nsec = 20000000,
        };
        nanosleep(&signalfd_delay, NULL);
        _exit(kill(getppid(), SIGUSR1) == 0 ? 0 : 1);
    }
    memset(&signal_info, 0, sizeof(signal_info));
    if (read(blocking_signalfd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1) {
        return 391;
    }
    signalfd_child_status = 0;
    if (waitpid(blocking_signalfd_child, &signalfd_child_status, 0) !=
            blocking_signalfd_child ||
        !WIFEXITED(signalfd_child_status) ||
        WEXITSTATUS(signalfd_child_status) != 0 ||
        close(blocking_signalfd) != 0) {
        return 392;
    }
    errno = 0;
    if (syscall(SYS_signalfd4, signalfd_fd, &signalfd_mask, 7, 0) != -1 ||
        errno != EINVAL) {
        return 387;
    }
    errno = 0;
    if (signalfd(-1, &signalfd_mask, 0x400000) != -1 || errno != EINVAL) {
        return 388;
    }
    if (close(signalfd_received) != 0 ||
        close(signalfd_socket[0]) != 0 ||
        close(signalfd_socket[1]) != 0 ||
        close(signalfd_epfd) != 0 || close(signalfd_fd) != 0 ||
        sigprocmask(SIG_SETMASK, &signalfd_saved_mask, NULL) != 0) {
        return 389;
    }
    sigset_t sigqueue_saved_mask;
    sigset_t sigqueue_mask;
    sigemptyset(&sigqueue_mask);
    sigaddset(&sigqueue_mask, SIGUSR1);
    int sigqueue_fd = signalfd(-1, &sigqueue_mask, SFD_NONBLOCK);
    siginfo_t queued_info = {
        .si_signo = SIGUSR1,
        .si_code = SI_QUEUE,
        .si_pid = getpid(),
        .si_uid = getuid(),
        .si_value.sival_ptr = (void *)0x515545554544ULL,
    };
    if (sigprocmask(SIG_BLOCK, &sigqueue_mask, &sigqueue_saved_mask) != 0 ||
        sigqueue_fd < 0 ||
        syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1,
                &queued_info) != 0 ||
        read(sigqueue_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != SIGUSR1 ||
        signal_info.ssi_code != SI_QUEUE ||
        signal_info.ssi_pid != (uint32_t)getpid() ||
        signal_info.ssi_uid != (uint32_t)getuid() ||
        signal_info.ssi_ptr != 0x515545554544ULL) {
        return 393;
    }
    queued_info.si_value.sival_ptr = (void *)0x544744515545ULL;
    if (syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(),
                SIGUSR1, &queued_info) != 0 ||
        read(sigqueue_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_ptr != 0x544744515545ULL) {
        return 394;
    }
    queued_info.si_value.sival_ptr = (void *)0x574149544544ULL;
    siginfo_t waited_info = {0};
    if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1,
                &queued_info) != 0 ||
        syscall(SYS_rt_sigtimedwait, &sigqueue_mask, &waited_info,
                NULL, 8) != SIGUSR1 ||
        waited_info.si_code != SI_QUEUE ||
        waited_info.si_pid != getpid() ||
        waited_info.si_uid != getuid() ||
        waited_info.si_value.sival_ptr != (void *)0x574149544544ULL) {
        return 398;
    }
    errno = 0;
    if (syscall(SYS_rt_sigqueueinfo, getpid(), 0, &queued_info) != -1 ||
        errno != EINVAL ||
        syscall(SYS_rt_sigqueueinfo, getpid(), SIGUSR1, NULL) != -1 ||
        errno != EFAULT ||
        syscall(SYS_rt_tgsigqueueinfo, getpid(), 0,
                SIGUSR1, &queued_info) != -1 ||
        errno != EINVAL) {
        return 395;
    }
    pid_t forged_source = fork();
    if (forged_source < 0) {
        return 396;
    }
    if (forged_source == 0) {
        siginfo_t forged = {
            .si_signo = SIGUSR1,
            .si_code = SI_USER,
            .si_pid = getpid(),
            .si_uid = getuid(),
        };
        errno = 0;
        int result = syscall(SYS_rt_sigqueueinfo, getppid(),
                             SIGUSR1, &forged);
        _exit(result == -1 && errno == EPERM ? 0 : 1);
    }
    int forged_status = 0;
    if (waitpid(forged_source, &forged_status, 0) != forged_source ||
        !WIFEXITED(forged_status) || WEXITSTATUS(forged_status) != 0 ||
        close(sigqueue_fd) != 0 ||
        sigprocmask(SIG_SETMASK, &sigqueue_saved_mask, NULL) != 0) {
        return 397;
    }
    sigset_t realtime_saved_mask;
    sigset_t realtime_mask;
    sigemptyset(&realtime_mask);
    sigaddset(&realtime_mask, SIGRTMIN);
    int realtime_fd = signalfd(-1, &realtime_mask, SFD_NONBLOCK);
    if (sigprocmask(SIG_BLOCK, &realtime_mask,
                    &realtime_saved_mask) != 0 ||
        realtime_fd < 0) {
        return 399;
    }
    queued_info.si_signo = SIGRTMIN;
    queued_info.si_code = SI_QUEUE;
    queued_info.si_value.sival_int = 0x11111111;
    if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMIN,
                &queued_info) != 0) {
        return 400;
    }
    queued_info.si_value.sival_int = 0x22222222;
    if (syscall(SYS_rt_sigqueueinfo, getpid(), SIGRTMIN,
                &queued_info) != 0 ||
        read(realtime_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != (uint32_t)SIGRTMIN ||
        signal_info.ssi_ptr != 0x11111111ULL ||
        read(realtime_fd, &signal_info, sizeof(signal_info)) !=
            (ssize_t)sizeof(signal_info) ||
        signal_info.ssi_signo != (uint32_t)SIGRTMIN ||
        signal_info.ssi_ptr != 0x22222222ULL ||
        close(realtime_fd) != 0 ||
        sigprocmask(SIG_SETMASK, &realtime_saved_mask, NULL) != 0) {
        return 401;
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
    struct cachestat_range cache_range = {
        .off = 0,
        .len = 4096,
    };
    struct cachestat cache_status = {0};
    if (syscall(SYS_cachestat, fd, &cache_range, &cache_status, 0) != 0 ||
        cache_status.nr_cache == 0) {
        return 614;
    }
    struct file_attr file_attributes = {
        .fa_xflags = UINT64_MAX,
    };
    if (syscall(SYS_file_getattr, fd, NULL, &file_attributes,
                sizeof(file_attributes), AT_EMPTY_PATH) != 0 ||
        file_attributes.fa_xflags != 0 ||
        file_attributes.fa_extsize != 0 ||
        file_attributes.fa_projid != 0) {
        return 620;
    }
    memset(&file_attributes, 0, sizeof(file_attributes));
    errno = 0;
    if (syscall(SYS_file_setattr, fd, NULL, &file_attributes,
                sizeof(file_attributes), AT_EMPTY_PATH) != -1 ||
        errno != EROFS) {
        return 621;
    }
    errno = 0;
    if (syscall(SYS_file_getattr, fd, NULL, &file_attributes, 23,
                AT_EMPTY_PATH) != -1 || errno != EINVAL) {
        return 622;
    }
    struct file_handle *file_identity = calloc(1, sizeof(struct file_handle) + 8);
    int file_mount_id = 0;
    if (!file_identity) {
        return 630;
    }
    file_identity->handle_bytes = 8;
    if (syscall(SYS_name_to_handle_at, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                file_identity, &file_mount_id, AT_SYMLINK_FOLLOW) != 0 ||
        file_identity->handle_bytes != 8 ||
        file_mount_id == 0) {
        return 631;
    }
    int handle_fd = syscall(SYS_open_by_handle_at, AT_FDCWD,
                            file_identity, O_RDONLY | O_CLOEXEC);
    unsigned char handle_magic[4] = {0};
    if (handle_fd < 0 ||
        read(handle_fd, handle_magic, sizeof(handle_magic)) !=
            (ssize_t)sizeof(handle_magic) ||
        handle_magic[0] != 0x7f || handle_magic[1] != 'E' ||
        handle_magic[2] != 'L' || handle_magic[3] != 'F' ||
        close(handle_fd) != 0) {
        return 632;
    }
    file_identity->handle_bytes = 4;
    errno = 0;
    if (syscall(SYS_name_to_handle_at, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                file_identity, &file_mount_id, 0) != -1 ||
        errno != EOVERFLOW || file_identity->handle_bytes != 8) {
        return 633;
    }
    free(file_identity);
    int mount_tree_fd = syscall(SYS_open_tree, AT_FDCWD, "/",
                                OPEN_TREE_CLOEXEC);
    struct mount_attr mount_attributes = {0};
    errno = 0;
    if (mount_tree_fd < 0 ||
        fcntl(mount_tree_fd, F_GETFD) != FD_CLOEXEC ||
        syscall(SYS_mount_setattr, AT_FDCWD, "/", AT_RECURSIVE,
                &mount_attributes, sizeof(mount_attributes)) != -1 ||
        errno != EROFS ||
        syscall(SYS_move_mount, mount_tree_fd, NULL, AT_FDCWD, "/",
                MOVE_MOUNT_F_EMPTY_PATH) != -1 ||
        errno != EROFS ||
        close(mount_tree_fd) != 0) {
        return 635;
    }
    int attributed_tree_fd = syscall(SYS_open_tree_attr, AT_FDCWD, "/",
                                     OPEN_TREE_CLOEXEC,
                                     &mount_attributes,
                                     sizeof(mount_attributes));
    if (attributed_tree_fd < 0 || close(attributed_tree_fd) != 0) {
        return 643;
    }
    mount_attributes.attr_set = MOUNT_ATTR_RDONLY;
    errno = 0;
    if (syscall(SYS_open_tree_attr, AT_FDCWD, "/", OPEN_TREE_CLOEXEC,
                &mount_attributes, sizeof(mount_attributes)) != -1 ||
        errno != EROFS) {
        return 644;
    }
    int fs_context_fd = syscall(SYS_fsopen, "jasperfs", FSOPEN_CLOEXEC);
    if (fs_context_fd < 0 ||
        syscall(SYS_fsconfig, fs_context_fd,
                FSCONFIG_CMD_CREATE, NULL, NULL, 0) != 0) {
        return 636;
    }
    int created_mount_fd = syscall(SYS_fsmount, fs_context_fd,
                                   FSMOUNT_CLOEXEC, 0);
    int picked_mount_fd = syscall(SYS_fspick, AT_FDCWD, "/",
                                  FSPICK_CLOEXEC);
    if (created_mount_fd < 0 || picked_mount_fd < 0 ||
        fcntl(created_mount_fd, F_GETFD) != FD_CLOEXEC ||
        fcntl(picked_mount_fd, F_GETFD) != FD_CLOEXEC ||
        close(created_mount_fd) != 0 ||
        close(picked_mount_fd) != 0 ||
        close(fs_context_fd) != 0) {
        return 637;
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
    int kcmp_other = open("/usr/bin/true", O_RDONLY | O_CLOEXEC);
    errno = 0;
    if (kcmp_other < 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE,
                fd, dup_fd) != 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE,
                fd, kcmp_other) == 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILES,
                fd, dup_fd) != 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_FILE,
                fd, 9999) != -1 || errno != EBADF) {
        return 558;
    }
    errno = 0;
    if (syscall(SYS_kcmp, getpid(), getpid(), 99, fd, fd) != -1 ||
        errno != EINVAL ||
        syscall(SYS_kcmp, INT_MAX, getpid(), KCMP_FILES,
                fd, fd) != -1 ||
        errno != ESRCH) {
        return 559;
    }
    int kcmp_epoll = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event kcmp_interest = {
        .events = EPOLLIN,
        .data.u64 = 0x4b434d5045504f4cULL,
    };
    struct kcmp_epoll_slot kcmp_slot = {
        .efd = (uint32_t)kcmp_epoll,
        .tfd = (uint32_t)fd,
        .toff = 0,
    };
    if (kcmp_epoll < 0 ||
        epoll_ctl(kcmp_epoll, EPOLL_CTL_ADD, fd,
                  &kcmp_interest) != 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_EPOLL_TFD,
                fd, &kcmp_slot) != 0 ||
        syscall(SYS_kcmp, getpid(), getpid(), KCMP_EPOLL_TFD,
                kcmp_other, &kcmp_slot) == 0 ||
        close(kcmp_epoll) != 0) {
        return 617;
    }
    int kcmp_pipe[2];
    if (pipe2(kcmp_pipe, O_CLOEXEC) != 0) {
        return 560;
    }
    pid_t kcmp_child = fork();
    if (kcmp_child < 0) {
        return 561;
    }
    if (kcmp_child == 0) {
        close(kcmp_pipe[1]);
        char byte = 0;
        int result = read(kcmp_pipe[0], &byte, 1);
        _exit(result == 1 && byte == 'K' ? 0 : 1);
    }
    close(kcmp_pipe[0]);
    if (syscall(SYS_kcmp, getpid(), kcmp_child, KCMP_FILE,
                fd, fd) != 0 ||
        syscall(SYS_kcmp, getpid(), kcmp_child, KCMP_VM,
                fd, fd) == 0 ||
        syscall(SYS_kcmp, getpid(), kcmp_child, KCMP_FILES,
                fd, fd) == 0) {
        return 562;
    }
    int kcmp_status = 0;
    if (write(kcmp_pipe[1], "K", 1) != 1 ||
        waitpid(kcmp_child, &kcmp_status, 0) != kcmp_child ||
        !WIFEXITED(kcmp_status) || WEXITSTATUS(kcmp_status) != 0 ||
        close(kcmp_pipe[1]) != 0 || close(kcmp_other) != 0) {
        return 563;
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
    int pipe_default_capacity = fcntl(pipe_fds[0], F_GETPIPE_SZ);
    int pipe_resized_capacity = fcntl(pipe_fds[1], F_SETPIPE_SZ, 8192);
    errno = 0;
    if (pipe_default_capacity != 65536 ||
        pipe_resized_capacity != 8192 ||
        fcntl(pipe_fds[0], F_GETPIPE_SZ) != 8192 ||
        fcntl(fd, F_GETPIPE_SZ) != -1 || errno != EINVAL) {
        return 687;
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
    int allocate_fd = memfd_create("fallocate", 0);
    if (allocate_fd < 0 ||
        readahead(allocate_fd, 0, 4096) != 0 ||
        posix_fadvise(allocate_fd, 0, 0, POSIX_FADV_NORMAL) != 0 ||
        sync_file_range(allocate_fd, 0, 0, SYNC_FILE_RANGE_WRITE) != 0 ||
        fallocate(allocate_fd, 0, 0, 8192) != 0) {
        return 316;
    }
    struct stat allocate_stat;
    if (fstat(allocate_fd, &allocate_stat) != 0 ||
        allocate_stat.st_size != 8192 ||
        pwrite(allocate_fd, "ABCDEFGH", 8, 96) != 8 ||
        fallocate(allocate_fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                  96, 8) != 0) {
        return 317;
    }
    unsigned char allocate_zeroes[8];
    memset(allocate_zeroes, 0xff, sizeof(allocate_zeroes));
    if (pread(allocate_fd, allocate_zeroes, sizeof(allocate_zeroes), 96) !=
            (ssize_t)sizeof(allocate_zeroes)) {
        return 318;
    }
    for (size_t index = 0; index < sizeof(allocate_zeroes); index++) {
        if (allocate_zeroes[index] != 0) {
            return 319;
        }
    }
    errno = 0;
    if (fallocate(allocate_fd, FALLOC_FL_KEEP_SIZE, 8192, 4096) != -1 ||
        errno != EOPNOTSUPP || close(allocate_fd) != 0) {
        return 320;
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
    futex_requeue_source = 0;
    futex_requeue_target = 0;
    atomic_store(&futex_requeue_started, 0);
    atomic_store(&futex_requeue_finished, 0);
    pthread_t requeue_threads[2];
    if (pthread_create(&requeue_threads[0], NULL, futex_requeue_waiter,
                       NULL) != 0 ||
        pthread_create(&requeue_threads[1], NULL, futex_requeue_waiter,
                       NULL) != 0) {
        return 308;
    }
    while (atomic_load_explicit(&futex_requeue_started,
                                memory_order_acquire) != 2) {
        sched_yield();
    }
    errno = 0;
    if (syscall(SYS_futex, &futex_requeue_source,
                FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG, 0, 2,
                &futex_requeue_target, 1) != -1 || errno != EAGAIN) {
        return 309;
    }
    if (syscall(SYS_futex, &futex_requeue_source,
                FUTEX_CMP_REQUEUE | FUTEX_PRIVATE_FLAG, 0, 2,
                &futex_requeue_target, 0) != 2) {
        return 310;
    }
    nanosleep(&futex_delay, NULL);
    if (atomic_load_explicit(&futex_requeue_finished,
                             memory_order_acquire) != 0 ||
        syscall(SYS_futex, &futex_requeue_target,
                FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 2,
                NULL, NULL, 0) != 2) {
        return 311;
    }
    if (pthread_join(requeue_threads[0], &futex_result0) != 0 ||
        pthread_join(requeue_threads[1], &futex_result1) != 0 ||
        futex_result0 != 0 || futex_result1 != 0) {
        return 312;
    }
    atomic_store(&futex_requeue_started, 0);
    atomic_store(&futex_requeue_finished, 0);
    if (pthread_create(&requeue_threads[0], NULL, futex_requeue_waiter,
                       NULL) != 0) {
        return 313;
    }
    while (atomic_load_explicit(&futex_requeue_started,
                                memory_order_acquire) != 1) {
        sched_yield();
    }
    if (syscall(SYS_futex, &futex_requeue_source,
                FUTEX_REQUEUE | FUTEX_PRIVATE_FLAG, 0, 1,
                &futex_requeue_target, 0) != 1 ||
        syscall(SYS_futex, &futex_requeue_target,
                FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1,
                NULL, NULL, 0) != 1 ||
        pthread_join(requeue_threads[0], &futex_result0) != 0 ||
        futex_result0 != 0) {
        return 314;
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
        struct timespec shared_timeout = {.tv_sec = 2, .tv_nsec = 0};
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
    errno = 0;
    int epoll_result = epoll_wait(epfd, epoll_ready, 1, 1000);
    int epoll_errno = errno;
    ssize_t epoll_bytes = -1;
    if (epoll_result == 1) {
        epoll_bytes = read(epoll_pipe[0], memfd_io, 1);
    }
    if (epoll_result != 1 || (epoll_ready[0].events & EPOLLIN) == 0 ||
        epoll_ready[0].data.u64 != 0x4a5345504f4c4cULL ||
        epoll_bytes != 1 || memfd_io[0] != 'E') {
        printf("epoll-event-fail result=%d errno=%d events=%#x data=%#llx "
               "bytes=%zd byte=%#x\n",
               epoll_result, epoll_errno, epoll_ready[0].events,
               (unsigned long long)epoll_ready[0].data.u64,
               epoll_bytes, epoll_bytes == 1 ? memfd_io[0] : 0);
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
                                      1000, &epoll_empty_mask,
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
    struct jasper_ion_fd_data ion_share_other = {
        .handle = ion_allocation.handle,
        .fd = -1,
    };
    if (ioctl(ion_fd, JASPER_ION_IOC_SHARE, &ion_share_other) != 0 ||
        ion_share_other.fd < 0) {
        return 321;
    }
    int ion_duplicate = dup(ion_share.fd);
    if (ion_duplicate < 0 || flock(ion_share.fd, LOCK_EX) != 0 ||
        flock(ion_duplicate, LOCK_EX | LOCK_NB) != 0 ||
        flock(ion_share.fd, LOCK_UN) != 0) {
        return 322;
    }
    if (flock(ion_share.fd, LOCK_EX) != 0) {
        return 323;
    }
    errno = 0;
    if (flock(ion_share_other.fd, LOCK_EX | LOCK_NB) != -1 ||
        errno != EWOULDBLOCK || flock(ion_share.fd, LOCK_UN) != 0 ||
        flock(ion_share_other.fd, LOCK_EX | LOCK_NB) != 0 ||
        flock(ion_share_other.fd, LOCK_UN) != 0 ||
        close(ion_duplicate) != 0) {
        return 324;
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
        close(ion_share_other.fd) != 0 ||
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
        unsigned char write_buffer[4 + sizeof(struct binder_transaction_data_sg)];
        struct binder_transaction_data_sg request_sg = {
            .transaction_data = request,
            .buffers_size = sizeof(request_data),
        };
        memcpy(write_buffer, &(uint32_t){BC_TRANSACTION_SG}, 4);
        memcpy(write_buffer + 4, &request_sg, sizeof(request_sg));
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
        exchange.write_size = 4 + sizeof(second_request);
        exchange.write_buffer = (binder_uintptr_t)write_buffer;
        exchange.read_size = sizeof(read_buffer);
        exchange.read_buffer = (binder_uintptr_t)read_buffer;
        if (ioctl(client, BINDER_WRITE_READ, &exchange) != 0 ||
            exchange.write_consumed != 4 + sizeof(second_request) ||
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
        struct flat_binder_object manager_object = {
            .hdr.type = BINDER_TYPE_BINDER,
            .flags = FLAT_BINDER_FLAG_ACCEPTS_FDS,
            .binder = (binder_uintptr_t)(uintptr_t)&manager_object,
            .cookie = 0x5151,
        };
        struct flat_binder_object invalid_manager = manager_object;
        invalid_manager.hdr.type = BINDER_TYPE_FD;
        errno = 0;
        if (ioctl(server, BINDER_SET_CONTEXT_MGR_EXT, &invalid_manager) != -1 ||
            errno != EINVAL) {
            return 190;
        }
        int context_result =
            ioctl(server, BINDER_SET_CONTEXT_MGR_EXT, &manager_object);
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
    struct binder_transaction_data_sg response_sg = {
        .transaction_data = response,
        .buffers_size = sizeof(response_object) + sizeof(response_offset),
    };
    unsigned char server_write[128];
    size_t server_offset = 0;
    memcpy(server_write + server_offset, &(uint32_t){BC_FREE_BUFFER}, 4);
    server_offset += 4;
    binder_uintptr_t received_pointer = received.data.ptr.buffer;
    memcpy(server_write + server_offset, &received_pointer,
           sizeof(received_pointer));
    server_offset += sizeof(received_pointer);
    memcpy(server_write + server_offset, &(uint32_t){BC_REPLY_SG}, 4);
    server_offset += 4;
    memcpy(server_write + server_offset, &response_sg, sizeof(response_sg));
    server_offset += sizeof(response_sg);
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
    if (poll(&poll_read, 1, 1000) != 1 ||
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
    struct timespec ppoll_timeout = {.tv_sec = 1, .tv_nsec = 0};
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
    struct timeval select_timeout = {.tv_sec = 1, .tv_usec = 0};
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
    if (setpriority(PRIO_PROCESS, getpid(), 5) != 0 ||
        getpriority(PRIO_PROCESS, getpid()) != 5 ||
        setpriority(PRIO_PROCESS, getpid(), 0) != 0 ||
        getpriority(PRIO_PROCESS, getpid()) != 0 ||
        sched_get_priority_max(SCHED_OTHER) != 0 ||
        sched_get_priority_min(SCHED_OTHER) != 0 ||
        sched_get_priority_max(SCHED_FIFO) != 99 ||
        sched_get_priority_min(SCHED_FIFO) != 1) {
        return 317;
    }
    struct sched_param scheduler_set = {.sched_priority = 0};
    struct timespec scheduler_interval = {0};
    if (sched_setparam(0, &scheduler_set) != 0 ||
        sched_rr_get_interval(0, &scheduler_interval) != 0 ||
        scheduler_interval.tv_sec != 0 ||
        scheduler_interval.tv_nsec != 2000000) {
        return 318;
    }
    scheduler_set.sched_priority = 3;
    errno = 0;
    if (sched_setparam(0, &scheduler_set) != -1 || errno != EINVAL) {
        return 319;
    }
    struct sched_attr scheduler_attr = {.size = sizeof(scheduler_attr)};
    if (syscall(SYS_sched_getattr, 0, &scheduler_attr,
                sizeof(scheduler_attr), 0) != 0 ||
        scheduler_attr.sched_policy != SCHED_OTHER ||
        scheduler_attr.sched_nice != 0 ||
        scheduler_attr.sched_priority != 0) {
        return 320;
    }
    scheduler_attr.sched_nice = 7;
    if (syscall(SYS_sched_setattr, 0, &scheduler_attr, 0) != 0 ||
        syscall(SYS_sched_getattr, 0, &scheduler_attr,
                sizeof(scheduler_attr), 0) != 0 ||
        scheduler_attr.sched_nice != 7) {
        return 321;
    }
    scheduler_attr.sched_nice = 0;
    if (syscall(SYS_sched_setattr, 0, &scheduler_attr, 0) != 0) {
        return 322;
    }
    scheduler_attr.sched_policy = SCHED_FIFO;
    errno = 0;
    if (syscall(SYS_sched_setattr, 0, &scheduler_attr, 0) != -1 ||
        errno != EOPNOTSUPP) {
        return 323;
    }
    scheduler_attr.sched_policy = SCHED_OTHER;
    scheduler_attr.sched_flags = SCHED_FLAG_RESET_ON_FORK;
    errno = 0;
    if (syscall(SYS_sched_setattr, 0, &scheduler_attr, 0) != -1 ||
        errno != EOPNOTSUPP) {
        return 324;
    }
    scheduler_attr.sched_flags = 0;
    if (syscall(SYS_sched_getattr, 0, &scheduler_attr,
                sizeof(scheduler_attr), 0) != 0 ||
        scheduler_attr.sched_policy != SCHED_OTHER ||
        scheduler_attr.sched_flags != 0 ||
        scheduler_attr.sched_nice != 0) {
        return 325;
    }
    errno = 0;
    if (syscall(SYS_sched_getattr, 0, &scheduler_attr, 47, 0) != -1 ||
        errno != EINVAL) {
        return 326;
    }
    scheduler_attr.size = 47;
    errno = 0;
    if (syscall(SYS_sched_setattr, 0, &scheduler_attr, 0) != -1 ||
        errno != EINVAL) {
        return 327;
    }
    scheduler_attr.size = sizeof(scheduler_attr);
    errno = 0;
    if (syscall(SYS_sched_getattr, 0, &scheduler_attr,
                sizeof(scheduler_attr), 1) != -1 ||
        errno != EINVAL) {
        return 328;
    }
    errno = 0;
    if (syscall(SYS_sched_getattr, INT_MAX, &scheduler_attr,
                sizeof(scheduler_attr), 0) != -1 ||
        errno != ESRCH) {
        return 329;
    }
    char main_thread_name[16] = {0};
    if (prctl(PR_SET_NAME, "main-thread", 0, 0, 0) != 0 ||
        prctl(PR_GET_NAME, main_thread_name, 0, 0, 0) != 0 ||
        strcmp(main_thread_name, "main-thread") != 0) {
        return 330;
    }
    struct prctl_thread_result prctl_result = {
        .set_result = -1,
        .get_result = -1,
    };
    pthread_t prctl_thread;
    if (pthread_create(&prctl_thread, NULL, prctl_name_worker,
                       &prctl_result) != 0 ||
        pthread_join(prctl_thread, NULL) != 0) {
        return 331;
    }
    if (prctl_result.set_result != 0 || prctl_result.get_result != 0 ||
        strcmp(prctl_result.inherited, "main-thread") != 0 ||
        strcmp(prctl_result.changed, "worker-thread") != 0 ||
        prctl(PR_GET_NAME, main_thread_name, 0, 0, 0) != 0 ||
        strcmp(main_thread_name, "main-thread") != 0) {
        return 332;
    }
    errno = 0;
    if (prctl(0x7fffffff, 0, 0, 0, 0) != -1 || errno != EINVAL) {
        return 333;
    }
    struct timespec privileged_time = {0};
    struct timeval privileged_timeval = {0};
    struct timex privileged_timex = {0};
    errno = 0;
    if (syscall(SYS_clock_settime, CLOCK_REALTIME, &privileged_time) != -1 ||
        errno != EPERM) {
        return 334;
    }
    errno = 0;
    if (syscall(SYS_settimeofday, &privileged_timeval, NULL) != -1 ||
        errno != EPERM) {
        return 335;
    }
    errno = 0;
    if (syscall(SYS_adjtimex, &privileged_timex) != -1 ||
        errno != EPERM) {
        return 336;
    }
    errno = 0;
    if (syscall(SYS_clock_adjtime, CLOCK_REALTIME,
                &privileged_timex) != -1 || errno != EPERM) {
        return 337;
    }
    errno = 0;
    if (syscall(SYS_sethostname, "jasper", 6) != -1 ||
        errno != EPERM) {
        return 338;
    }
    errno = 0;
    if (syscall(SYS_setdomainname, "jasper", 6) != -1 ||
        errno != EPERM) {
        return 339;
    }
    errno = 0;
    if (reboot(RB_AUTOBOOT) != -1 || errno != EPERM) {
        return 340;
    }
    int timer_fd = timerfd_create(CLOCK_MONOTONIC,
                                  TFD_NONBLOCK | TFD_CLOEXEC);
    if (timer_fd < 0 || (fcntl(timer_fd, F_GETFD) & FD_CLOEXEC) == 0) {
        return 349;
    }
    struct itimerspec timer_value = {
        .it_value = {.tv_sec = 0, .tv_nsec = 20000000},
    };
    if (timerfd_settime(timer_fd, 0, &timer_value, NULL) != 0) {
        return 350;
    }
    struct itimerspec timer_current = {0};
    if (timerfd_gettime(timer_fd, &timer_current) != 0 ||
        timer_current.it_value.tv_sec != 0 ||
        timer_current.it_value.tv_nsec == 0 ||
        timer_current.it_value.tv_nsec > 200000000) {
        return 359;
    }
    struct pollfd timer_poll = {
        .fd = timer_fd,
        .events = POLLIN,
    };
    if (poll(&timer_poll, 1, 1000) != 1 ||
        (timer_poll.revents & POLLIN) == 0) {
        return 351;
    }
    uint64_t timer_expirations = 0;
    if (read(timer_fd, &timer_expirations, sizeof(timer_expirations)) !=
            sizeof(timer_expirations) ||
        timer_expirations == 0) {
        return 352;
    }
    errno = 0;
    if (read(timer_fd, &timer_expirations, sizeof(timer_expirations)) != -1 ||
        errno != EAGAIN) {
        return 353;
    }
    memset(&timer_value, 0, sizeof(timer_value));
    if (timerfd_settime(timer_fd, 0, &timer_value, NULL) != 0 ||
        poll(&timer_poll, 1, 20) != 0) {
        return 354;
    }
    timer_value.it_interval = (struct timespec){.tv_sec = 0, .tv_nsec = 10000000};
    timer_value.it_value = (struct timespec){.tv_sec = 0, .tv_nsec = 10000000};
    int timer_epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event timer_interest = {
        .events = EPOLLIN,
        .data.u64 = 0x54494d45524644ULL,
    };
    struct epoll_event timer_ready = {0};
    if (timer_epfd < 0 ||
        epoll_ctl(timer_epfd, EPOLL_CTL_ADD, timer_fd,
                  &timer_interest) != 0 ||
        timerfd_settime(timer_fd, 0, &timer_value, NULL) != 0 ||
        epoll_wait(timer_epfd, &timer_ready, 1, 1000) != 1 ||
        (timer_ready.events & EPOLLIN) == 0 ||
        timer_ready.data.u64 != 0x54494d45524644ULL ||
        epoll_ctl(timer_epfd, EPOLL_CTL_DEL, timer_fd, NULL) != 0) {
        return 355;
    }
    if (read(timer_fd, &timer_expirations, sizeof(timer_expirations)) !=
        sizeof(timer_expirations)
        || timer_expirations == 0) {
        return 356;
    }
    memset(&timer_value, 0, sizeof(timer_value));
    if (timerfd_settime(timer_fd, 0, &timer_value, NULL) != 0 ||
        close(timer_epfd) != 0 || close(timer_fd) != 0) {
        return 357;
    }
    errno = 0;
    if (timerfd_create((clockid_t)12345, 0) != -1 || errno != EINVAL) {
        return 358;
    }
    timer_t posix_timer = (timer_t)-1;
    struct sigevent posix_event = {.sigev_notify = SIGEV_NONE};
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &posix_event,
                &posix_timer) != 0 || posix_timer == (timer_t)-1) {
        return 366;
    }
    struct itimerspec posix_values = {
        .it_value = {.tv_sec = 0, .tv_nsec = 20000000},
    };
    struct itimerspec posix_current = {0};
    if (syscall(SYS_timer_settime, posix_timer, 0, &posix_values,
                NULL) != 0 ||
        syscall(SYS_timer_gettime, posix_timer, &posix_current) != 0 ||
        posix_current.it_value.tv_sec != 0 ||
        posix_current.it_value.tv_nsec == 0) {
        return 367;
    }
    struct timespec posix_delay = {.tv_sec = 0, .tv_nsec = 40000000};
    if (nanosleep(&posix_delay, NULL) != 0 ||
        syscall(SYS_timer_getoverrun, posix_timer) != 0 ||
        syscall(SYS_timer_gettime, posix_timer, &posix_current) != 0 ||
        posix_current.it_value.tv_sec != 0 ||
        posix_current.it_value.tv_nsec != 0 ||
        syscall(SYS_timer_delete, posix_timer) != 0) {
        return 368;
    }
    errno = 0;
    if (syscall(SYS_timer_gettime, posix_timer, &posix_current) != -1 ||
        errno != EINVAL) {
        return 369;
    }
    posix_timer_signals = 0;
    if (signal(SIGUSR1, posix_timer_signal_handler) == SIG_ERR) {
        return 370;
    }
    struct sigevent signal_event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGUSR1,
    };
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &signal_event,
                &posix_timer) != 0) {
        return 371;
    }
    posix_values.it_value = (struct timespec){.tv_sec = 0, .tv_nsec = 20000000};
    if (syscall(SYS_timer_settime, posix_timer, 0, &posix_values,
                NULL) != 0) {
        return 372;
    }
    struct timespec signal_wait = {.tv_sec = 0, .tv_nsec = 500000000};
    errno = 0;
    long signal_sleep = nanosleep(&signal_wait, NULL);
    int signal_sleep_errno = errno;
    if ((signal_sleep != -1 || signal_sleep_errno != EINTR) &&
        posix_timer_signals == 0) {
        return 373;
    }
    for (int attempt = 0; attempt < 8 && posix_timer_signals == 0; attempt++) {
        syscall(SYS_getpid);
    }
    if (posix_timer_signals == 0 ||
        syscall(SYS_timer_delete, posix_timer) != 0) {
        return 374;
    }
    sigset_t timer_signal_set;
    sigset_t timer_old_mask;
    sigemptyset(&timer_signal_set);
    sigaddset(&timer_signal_set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &timer_signal_set, &timer_old_mask) != 0 ||
        syscall(SYS_timer_create, CLOCK_MONOTONIC, &signal_event,
                &posix_timer) != 0) {
        return 377;
    }
    posix_values.it_interval = (struct timespec){.tv_sec = 0, .tv_nsec = 10000000};
    posix_values.it_value = (struct timespec){.tv_sec = 0, .tv_nsec = 10000000};
    struct timespec overrun_delay = {.tv_sec = 0, .tv_nsec = 80000000};
    if (syscall(SYS_timer_settime, posix_timer, 0, &posix_values,
                NULL) != 0 ||
        nanosleep(&overrun_delay, NULL) != 0 ||
        syscall(SYS_timer_getoverrun, posix_timer) == 0) {
        return 378;
    }
    memset(&posix_values, 0, sizeof(posix_values));
    if (syscall(SYS_timer_settime, posix_timer, 0, &posix_values,
                NULL) != 0 ||
        syscall(SYS_timer_delete, posix_timer) != 0 ||
        sigprocmask(SIG_SETMASK, &timer_old_mask, NULL) != 0) {
        return 379;
    }
    struct sigevent unsupported_event = {.sigev_notify = SIGEV_THREAD};
    errno = 0;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &unsupported_event,
                &posix_timer) != -1 || errno != EOPNOTSUPP) {
        return 375;
    }
    errno = 0;
    if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &posix_event,
                NULL) != -1 || errno != EFAULT) {
        return 376;
    }
    interval_timer_signals = 0;
    if (signal(SIGALRM, interval_timer_signal_handler) == SIG_ERR) {
        return 393;
    }
    struct itimerval interval_value = {0};
    struct itimerval interval_old = {0};
    struct itimerval interval_current = {0};
    if (getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 0 ||
        interval_current.it_value.tv_sec != 0 ||
        interval_current.it_value.tv_usec != 0) {
        return 394;
    }
    if (alarm(2) != 0 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 0 ||
        interval_current.it_value.tv_sec < 0 ||
        interval_current.it_value.tv_sec > 2 ||
        (interval_current.it_value.tv_sec == 0 &&
         interval_current.it_value.tv_usec == 0)) {
        return 395;
    }
    unsigned int replaced_alarm = alarm(1);
    if (replaced_alarm == 0 || replaced_alarm > 2 ||
        alarm(0) == 0 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 0 ||
        interval_current.it_value.tv_sec != 0 ||
        interval_current.it_value.tv_usec != 0) {
        return 396;
    }
    interval_value.it_interval.tv_usec = 20000;
    interval_value.it_value.tv_usec = 40000;
    if (setitimer(ITIMER_REAL, &interval_value, &interval_old) != 0 ||
        interval_old.it_interval.tv_sec != 0 ||
        interval_old.it_interval.tv_usec != 0 ||
        interval_old.it_value.tv_sec != 0 ||
        interval_old.it_value.tv_usec != 0 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 20000 ||
        interval_current.it_value.tv_sec != 0 ||
        interval_current.it_value.tv_usec == 0 ||
        interval_current.it_value.tv_usec > 40000) {
        return 397;
    }
    memset(&interval_value, 0, sizeof(interval_value));
    if (setitimer(ITIMER_REAL, &interval_value, &interval_old) != 0 ||
        interval_old.it_interval.tv_sec != 0 ||
        interval_old.it_interval.tv_usec != 20000 ||
        interval_old.it_value.tv_sec != 0 ||
        interval_old.it_value.tv_usec == 0 ||
        interval_old.it_value.tv_usec > 40000 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_value.tv_sec != 0 ||
        interval_current.it_value.tv_usec != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 0) {
        return 398;
    }
    interval_timer_signals = 0;
    interval_value.it_interval.tv_usec = 10000;
    interval_value.it_value.tv_usec = 10000;
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != 0 ||
        wait_for_interval_signals(2) != 0) {
        return 399;
    }
    memset(&interval_old, 0, sizeof(interval_old));
    if (setitimer(ITIMER_REAL, NULL, &interval_old) != 0 ||
        interval_old.it_interval.tv_usec != 10000 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        interval_current.it_value.tv_sec != 0 ||
        interval_current.it_value.tv_usec != 0 ||
        interval_current.it_interval.tv_sec != 0 ||
        interval_current.it_interval.tv_usec != 0) {
        return 400;
    }
    sigset_t alarm_signal_set;
    sigset_t alarm_old_mask;
    sigemptyset(&alarm_signal_set);
    sigaddset(&alarm_signal_set, SIGALRM);
    if (sigprocmask(SIG_BLOCK, &alarm_signal_set, &alarm_old_mask) != 0) {
        return 401;
    }
    int alarm_signalfd =
        signalfd(-1, &alarm_signal_set, SFD_NONBLOCK | SFD_CLOEXEC);
    struct pollfd alarm_poll = {
        .fd = alarm_signalfd,
        .events = POLLIN,
    };
    struct signalfd_siginfo alarm_info = {0};
    interval_value.it_interval.tv_usec = 10000;
    interval_value.it_value.tv_usec = 10000;
    if (alarm_signalfd < 0 ||
        setitimer(ITIMER_REAL, &interval_value, NULL) != 0 ||
        poll(&alarm_poll, 1, 1000) != 1 ||
        read(alarm_signalfd, &alarm_info, sizeof(alarm_info)) !=
            (ssize_t)sizeof(alarm_info) ||
        alarm_info.ssi_signo != SIGALRM ||
        alarm_info.ssi_code != 128 ||
        alarm_info.ssi_pid != 0) {
        return 402;
    }
    memset(&interval_value, 0, sizeof(interval_value));
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != 0 ||
        close(alarm_signalfd) != 0 ||
        sigprocmask(SIG_SETMASK, &alarm_old_mask, NULL) != 0) {
        return 403;
    }
    errno = 0;
    if (getitimer(ITIMER_VIRTUAL, &interval_current) != -1 ||
        errno != EOPNOTSUPP) {
        return 404;
    }
    errno = 0;
    if (setitimer(ITIMER_PROF, &interval_value, NULL) != -1 ||
        errno != EOPNOTSUPP) {
        return 405;
    }
    errno = 0;
    if (getitimer(ITIMER_REAL, (struct itimerval *)(uintptr_t)1) != -1 ||
        errno != EFAULT) {
        return 406;
    }
    errno = 0;
    if (setitimer(ITIMER_REAL, (struct itimerval *)(uintptr_t)1, NULL) != -1 ||
        errno != EFAULT) {
        return 407;
    }
    interval_value.it_value.tv_usec = 1000000;
    errno = 0;
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != -1 ||
        errno != EINVAL) {
        return 408;
    }
    memset(&interval_value, 0, sizeof(interval_value));
    interval_value.it_value.tv_usec = 200000;
    errno = 0;
    if (setitimer(ITIMER_REAL, &interval_value,
                  (struct itimerval *)(uintptr_t)1) != -1 ||
        errno != EFAULT ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        (interval_current.it_value.tv_sec == 0 &&
         interval_current.it_value.tv_usec == 0)) {
        return 416;
    }
    memset(&interval_value, 0, sizeof(interval_value));
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != 0 ||
        alarm(1) != 0) {
        return 409;
    }
    pid_t interval_child = fork();
    if (interval_child < 0) {
        return 410;
    }
    if (interval_child == 0) {
        memset(&interval_current, 0, sizeof(interval_current));
        int child_result =
            getitimer(ITIMER_REAL, &interval_current) == 0 &&
            interval_current.it_value.tv_sec == 0 &&
            interval_current.it_value.tv_usec == 0;
        _exit(child_result ? 0 : 1);
    }
    int interval_child_status = 0;
    if (waitpid(interval_child, &interval_child_status, 0) != interval_child ||
        !WIFEXITED(interval_child_status) ||
        WEXITSTATUS(interval_child_status) != 0 ||
        alarm(0) == 0) {
        return 411;
    }
    for (int child_index = 0; child_index < 18; child_index++) {
        interval_child = fork();
        if (interval_child < 0) {
            return 412;
        }
        if (interval_child == 0) {
            interval_value.it_value.tv_sec = 1;
            _exit(setitimer(ITIMER_REAL, &interval_value, NULL) == 0 ? 0 : 1);
        }
        interval_child_status = 0;
        if (waitpid(interval_child, &interval_child_status, 0) !=
                interval_child ||
            !WIFEXITED(interval_child_status) ||
            WEXITSTATUS(interval_child_status) != 0) {
            return 413;
        }
    }
    memset(&interval_value, 0, sizeof(interval_value));
    interval_value.it_value.tv_usec = 10000;
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != 0 ||
        getitimer(ITIMER_REAL, &interval_current) != 0 ||
        (interval_current.it_value.tv_sec == 0 &&
         interval_current.it_value.tv_usec == 0)) {
        return 414;
    }
    memset(&interval_value, 0, sizeof(interval_value));
    if (setitimer(ITIMER_REAL, &interval_value, NULL) != 0) {
        return 415;
    }
    int legacy_fd =
        syscall(SYS_open, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                O_RDONLY | O_CLOEXEC, 0);
    unsigned char legacy_magic[4] = {0};
    if (legacy_fd < 0 ||
        read(legacy_fd, legacy_magic, sizeof(legacy_magic)) !=
            (ssize_t)sizeof(legacy_magic) ||
        memcmp(legacy_magic, "\177ELF", sizeof(legacy_magic)) != 0 ||
        close(legacy_fd) != 0) {
        return 417;
    }
    errno = 0;
    if (syscall(SYS_open, (const char *)(uintptr_t)1, O_RDONLY, 0) != -1 ||
        errno != EFAULT) {
        return 418;
    }
    errno = 0;
    if (syscall(SYS_creat, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                0644) != -1 || errno != EROFS) {
        return 419;
    }
    int legacy_pipe_fds[2] = {-1, -1};
    char legacy_pipe_byte = 'P';
    char legacy_pipe_result = 0;
    if (syscall(SYS_pipe, legacy_pipe_fds) != 0 ||
        write(legacy_pipe_fds[1], &legacy_pipe_byte, 1) != 1 ||
        read(legacy_pipe_fds[0], &legacy_pipe_result, 1) != 1 ||
        legacy_pipe_result != legacy_pipe_byte ||
        close(legacy_pipe_fds[0]) != 0 ||
        close(legacy_pipe_fds[1]) != 0) {
        return 420;
    }
    int legacy_root =
        syscall(SYS_open, "/", O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    unsigned char legacy_dents[1024] = {0};
    long legacy_dents_len =
        legacy_root < 0
            ? -1
            : syscall(SYS_getdents, legacy_root, legacy_dents,
                      sizeof(legacy_dents));
    struct legacy_dirent_probe *legacy_first =
        (struct legacy_dirent_probe *)legacy_dents;
    if (legacy_root < 0 || legacy_dents_len <= 0 ||
        legacy_first->d_reclen < 19 ||
        legacy_first->d_reclen > legacy_dents_len ||
        strcmp(legacy_first->d_name, ".") != 0 ||
        close(legacy_root) != 0) {
        return 421;
    }
    errno = 0;
    if (syscall(SYS_getdents, -1, legacy_dents, sizeof(legacy_dents)) != -1 ||
        errno != EBADF) {
        return 422;
    }
    struct robust_list_probe robust_probe = {0};
    void *robust_head = NULL;
    unsigned long robust_length = 0;
    if (syscall(SYS_set_robust_list, &robust_probe,
                sizeof(robust_probe)) != 0 ||
        syscall(SYS_get_robust_list, 0, &robust_head,
                &robust_length) != 0 ||
        robust_head != &robust_probe ||
        robust_length != sizeof(robust_probe)) {
        return 423;
    }
    errno = 0;
    if (syscall(SYS_get_robust_list, 0, (void *)(uintptr_t)1,
                &robust_length) != -1 ||
        errno != EFAULT) {
        return 424;
    }
    sigset_t tkill_signal_set;
    sigset_t tkill_old_mask;
    sigset_t tkill_pending;
    sigemptyset(&tkill_signal_set);
    sigaddset(&tkill_signal_set, SIGUSR2);
    if (sigprocmask(SIG_BLOCK, &tkill_signal_set, &tkill_old_mask) != 0 ||
        syscall(SYS_tkill, gettid(), SIGUSR2) != 0 ||
        sigpending(&tkill_pending) != 0 ||
        !sigismember(&tkill_pending, SIGUSR2) ||
        sigprocmask(SIG_SETMASK, &tkill_old_mask, NULL) != 0) {
        return 425;
    }
    pid_t legacy_fork_child = syscall(SYS_fork);
    if (legacy_fork_child < 0) {
        return 426;
    }
    if (legacy_fork_child == 0) {
        _exit(0);
    }
    int legacy_fork_status = 0;
    if (waitpid(legacy_fork_child, &legacy_fork_status, 0) !=
            legacy_fork_child ||
        !WIFEXITED(legacy_fork_status) ||
        WEXITSTATUS(legacy_fork_status) != 0) {
        return 427;
    }
    pid_t pause_child = fork();
    if (pause_child < 0) {
        return 428;
    }
    if (pause_child == 0) {
        struct itimerval pause_timer = {
            .it_value = {.tv_sec = 0, .tv_usec = 20000},
        };
        interval_timer_signals = 0;
        if (signal(SIGALRM, interval_timer_signal_handler) == SIG_ERR ||
            setitimer(ITIMER_REAL, &pause_timer, NULL) != 0) {
            _exit(2);
        }
        long pause_result = syscall(SYS_pause);
        int pause_errno = errno;
        _exit(pause_result == -1 && pause_errno == EINTR &&
                      interval_timer_signals > 0
                  ? 0
                  : 1);
    }
    int pause_child_status = 0;
    if (waitpid(pause_child, &pause_child_status, 0) != pause_child ||
        !WIFEXITED(pause_child_status) ||
        WEXITSTATUS(pause_child_status) != 0) {
        return 429;
    }
    pid_t waitid_child = fork();
    if (waitid_child < 0) {
        return 430;
    }
    if (waitid_child == 0) {
        _exit(42);
    }
    siginfo_t waitid_info = {0};
    if (syscall(SYS_waitid, P_PID, waitid_child, &waitid_info,
                WEXITED, NULL) != 0 ||
        waitid_info.si_pid != waitid_child ||
        waitid_info.si_status != 42 ||
        waitid_info.si_code != CLD_EXITED) {
        return 431;
    }
    memset(&waitid_info, 0xff, sizeof(waitid_info));
    errno = 0;
    if (syscall(SYS_waitid, P_ALL, 0, &waitid_info,
                WEXITED | WNOHANG, NULL) != -1 ||
        errno != ECHILD) {
        return 432;
    }
    pid_t waitid_live_child = fork();
    if (waitid_live_child < 0) {
        return 435;
    }
    if (waitid_live_child == 0) {
        pause();
        _exit(1);
    }
    memset(&waitid_info, 0xff, sizeof(waitid_info));
    if (syscall(SYS_waitid, P_PID, waitid_live_child, &waitid_info,
                WEXITED | WNOHANG, NULL) != 0 ||
        waitid_info.si_pid != 0 ||
        waitid_info.si_status != 0 ||
        kill(waitid_live_child, SIGTERM) != 0 ||
        waitpid(waitid_live_child, NULL, 0) != waitid_live_child) {
        return 436;
    }
    errno = 0;
    if (syscall(SYS_waitid, P_PGID, 0, &waitid_info,
                WEXITED, NULL) != -1 ||
        errno != EOPNOTSUPP) {
        return 433;
    }
    errno = 0;
    if (syscall(SYS_waitid, P_ALL, 0, &waitid_info,
                WEXITED | WNOWAIT, NULL) != -1 ||
        errno != EOPNOTSUPP) {
        return 434;
    }
    sigset_t timedwait_set;
    sigset_t timedwait_old;
    sigemptyset(&timedwait_set);
    sigaddset(&timedwait_set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &timedwait_set, &timedwait_old) != 0 ||
        kill(getpid(), SIGUSR1) != 0) {
        return 437;
    }
    memset(&waitid_info, 0, sizeof(waitid_info));
    long timedwait_signal =
        syscall(SYS_rt_sigtimedwait, &timedwait_set, &waitid_info,
                NULL, 8);
    if (timedwait_signal != SIGUSR1 ||
        waitid_info.si_signo != SIGUSR1 ||
        waitid_info.si_code != SI_USER ||
        waitid_info.si_pid != getpid()) {
        return 438;
    }
    sigset_t timedwait_empty;
    struct timespec timedwait_timeout = {
        .tv_sec = 0,
        .tv_nsec = 20000000,
    };
    sigemptyset(&timedwait_empty);
    errno = 0;
    if (syscall(SYS_rt_sigtimedwait, &timedwait_empty, NULL,
                &timedwait_timeout, 8) != -1 ||
        errno != EAGAIN) {
        return 439;
    }
    errno = 0;
    if (syscall(SYS_rt_sigtimedwait, &timedwait_empty, NULL,
                NULL, 7) != -1 ||
        errno != EINVAL ||
        sigprocmask(SIG_SETMASK, &timedwait_old, NULL) != 0) {
        return 440;
    }
    int sigsuspend_ready[2];
    if (pipe(sigsuspend_ready) != 0) {
        return 441;
    }
    pid_t sigsuspend_child = fork();
    if (sigsuspend_child < 0) {
        return 442;
    }
    if (sigsuspend_child == 0) {
        close(sigsuspend_ready[0]);
        sigset_t suspend_block;
        sigset_t suspend_empty;
        sigset_t suspend_current;
        sigemptyset(&suspend_block);
        sigaddset(&suspend_block, SIGUSR1);
        sigemptyset(&suspend_empty);
        sigsuspend_signals = 0;
        char ready = 'R';
        if (signal(SIGUSR1, sigsuspend_signal_handler) == SIG_ERR ||
            sigprocmask(SIG_BLOCK, &suspend_block, NULL) != 0 ||
            write(sigsuspend_ready[1], &ready, 1) != 1) {
            _exit(2);
        }
        long suspend_result =
            syscall(SYS_rt_sigsuspend, &suspend_empty, 8);
        int suspend_errno = errno;
        if (sigprocmask(SIG_BLOCK, NULL, &suspend_current) != 0) {
            _exit(3);
        }
        _exit(suspend_result == -1 && suspend_errno == EINTR &&
                      sigsuspend_signals > 0 &&
                      sigismember(&suspend_current, SIGUSR1)
                  ? 0
                  : 1);
    }
    close(sigsuspend_ready[1]);
    char sigsuspend_byte = 0;
    if (read(sigsuspend_ready[0], &sigsuspend_byte, 1) != 1 ||
        sigsuspend_byte != 'R' ||
        kill(sigsuspend_child, SIGUSR1) != 0 ||
        close(sigsuspend_ready[0]) != 0) {
        return 443;
    }
    int sigsuspend_status = 0;
    if (waitpid(sigsuspend_child, &sigsuspend_status, 0) !=
            sigsuspend_child ||
        !WIFEXITED(sigsuspend_status) ||
        WEXITSTATUS(sigsuspend_status) != 0) {
        return 444;
    }
    errno = 0;
    if (syscall(SYS_rt_sigsuspend, NULL, 8) != -1 ||
        errno != EFAULT) {
        return 445;
    }
    int legacy_epoll = syscall(SYS_epoll_create, 16);
    if (legacy_epoll < 0 || close(legacy_epoll) != 0) {
        return 446;
    }
    errno = 0;
    if (syscall(SYS_epoll_create, 0) != -1 || errno != EINVAL) {
        return 447;
    }
    int sendfile_input =
        syscall(SYS_open, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                O_RDONLY | O_CLOEXEC, 0);
    int sendfile_pipe[2];
    off_t sendfile_offset = 0;
    unsigned char sendfile_bytes[16] = {0};
    if (sendfile_input < 0 || syscall(SYS_pipe, sendfile_pipe) != 0 ||
        syscall(SYS_sendfile, sendfile_pipe[1], sendfile_input,
                &sendfile_offset, sizeof(sendfile_bytes)) !=
            (long)sizeof(sendfile_bytes) ||
        sendfile_offset != (off_t)sizeof(sendfile_bytes) ||
        read(sendfile_pipe[0], sendfile_bytes, sizeof(sendfile_bytes)) !=
            (ssize_t)sizeof(sendfile_bytes) ||
        memcmp(sendfile_bytes, "\177ELF", 4) != 0) {
        return 448;
    }
    if (lseek(sendfile_input, 0, SEEK_SET) != 0 ||
        syscall(SYS_sendfile, sendfile_pipe[1], sendfile_input,
                NULL, 4) != 4 ||
        lseek(sendfile_input, 0, SEEK_CUR) != 4) {
        return 449;
    }
    if (close(sendfile_pipe[0]) != 0 ||
        close(sendfile_pipe[1]) != 0 ||
        close(sendfile_input) != 0) {
        return 450;
    }
    void *locked_memory =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (locked_memory == MAP_FAILED ||
        syscall(SYS_mlock, locked_memory, 4096) != 0 ||
        syscall(SYS_mlock2, locked_memory, 4096, 1) != 0 ||
        syscall(SYS_munlock, locked_memory, 4096) != 0 ||
        syscall(SYS_mlockall, MCL_CURRENT | MCL_FUTURE) != 0 ||
        syscall(SYS_munlockall) != 0 ||
        munmap(locked_memory, 4096) != 0) {
        return 451;
    }
    errno = 0;
    if (syscall(SYS_mlock, (void *)(uintptr_t)1, 4096) != -1 ||
        errno != EINVAL) {
        return 452;
    }
    errno = 0;
    if (syscall(SYS_mlock2, locked_memory, 4096, 2) != -1 ||
        errno != EINVAL) {
        return 453;
    }
    errno = 0;
    if (syscall(SYS_mlockall, 8) != -1 || errno != EINVAL) {
        return 454;
    }
    struct jasper_open_how {
        uint64_t flags;
        uint64_t mode;
        uint64_t resolve;
    } open_how = {
        .flags = O_RDONLY | O_CLOEXEC,
    };
    int openat2_fd =
        syscall(SYS_openat2, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                &open_how, sizeof(open_how));
    unsigned char openat2_magic[4] = {0};
    if (openat2_fd < 0 ||
        read(openat2_fd, openat2_magic, sizeof(openat2_magic)) !=
            (ssize_t)sizeof(openat2_magic) ||
        memcmp(openat2_magic, "\177ELF", sizeof(openat2_magic)) != 0 ||
        close(openat2_fd) != 0) {
        return 455;
    }
    errno = 0;
    if (syscall(SYS_openat2, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                &open_how, 16) != -1 ||
        errno != EINVAL) {
        return 456;
    }
    open_how.resolve = 4;
    errno = 0;
    if (syscall(SYS_openat2, AT_FDCWD,
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                &open_how, sizeof(open_how)) != -1 ||
        errno != EOPNOTSUPP) {
        return 457;
    }
    const char *xattr_path = "/usr/lib/x86_64-linux-gnu/libc.so.6";
    int path_only_fd = open(xattr_path, O_PATH | O_CLOEXEC);
    struct stat path_only_status = {0};
    char path_only_byte = 0;
    errno = 0;
    if (path_only_fd < 0 ||
        (fcntl(path_only_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        (fcntl(path_only_fd, F_GETFL) & O_PATH) == 0 ||
        fstat(path_only_fd, &path_only_status) != 0 ||
        !S_ISREG(path_only_status.st_mode) ||
        read(path_only_fd, &path_only_byte, 1) != -1 ||
        errno != EBADF) {
        return 690;
    }
    int path_dir_fd = open("/usr/bin", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int path_exec_fd =
        path_dir_fd < 0
            ? -1
            : openat(path_dir_fd, "printf", O_PATH | O_CLOEXEC);
    memset(&path_only_status, 0, sizeof(path_only_status));
    if (path_dir_fd < 0 || path_exec_fd < 0 ||
        (fcntl(path_dir_fd, F_GETFL) & O_DIRECTORY) == 0 ||
        fstatat(path_exec_fd, "", &path_only_status,
                AT_EMPTY_PATH) != 0 ||
        !S_ISREG(path_only_status.st_mode) ||
        close(path_exec_fd) != 0 ||
        close(path_dir_fd) != 0 ||
        close(path_only_fd) != 0) {
        return 691;
    }
    const char *xattr_name = "user.jasper-test";
    char xattr_value = 'X';
    if (syscall(SYS_listxattr, xattr_path, NULL, 0) != 0 ||
        syscall(SYS_llistxattr, xattr_path, NULL, 0) != 0) {
        return 458;
    }
    errno = 0;
    if (syscall(SYS_getxattr, xattr_path, xattr_name,
                NULL, 0) != -1 ||
        errno != ENODATA) {
        return 459;
    }
    errno = 0;
    if (syscall(SYS_lgetxattr, xattr_path, xattr_name,
                NULL, 0) != -1 ||
        errno != ENODATA) {
        return 460;
    }
    errno = 0;
    if (syscall(SYS_setxattr, xattr_path, xattr_name,
                &xattr_value, 1, 0) != -1 ||
        errno != EROFS ||
        syscall(SYS_lsetxattr, xattr_path, xattr_name,
                &xattr_value, 1, 0) != -1 ||
        errno != EROFS) {
        return 461;
    }
    errno = 0;
    if (syscall(SYS_removexattr, xattr_path, xattr_name) != -1 ||
        errno != ENODATA ||
        syscall(SYS_lremovexattr, xattr_path, xattr_name) != -1 ||
        errno != ENODATA) {
        return 462;
    }
    int xattr_fd =
        syscall(SYS_open, xattr_path, O_RDONLY | O_CLOEXEC, 0);
    if (xattr_fd < 0 ||
        syscall(SYS_flistxattr, xattr_fd, NULL, 0) != 0) {
        return 463;
    }
    errno = 0;
    if (syscall(SYS_fgetxattr, xattr_fd, xattr_name,
                NULL, 0) != -1 ||
        errno != ENODATA) {
        return 464;
    }
    errno = 0;
    if (syscall(SYS_fsetxattr, xattr_fd, xattr_name,
                &xattr_value, 1, 0) != -1 ||
        errno != EROFS) {
        return 465;
    }
    errno = 0;
    if (syscall(SYS_fremovexattr, xattr_fd, xattr_name) != -1 ||
        errno != ENODATA ||
        close(xattr_fd) != 0) {
        return 466;
    }
    errno = 0;
    if (syscall(SYS_setxattr, xattr_path, xattr_name,
                &xattr_value, 1, 3) != -1 ||
        errno != EINVAL) {
        return 467;
    }
    struct jasper_xattr_args xattr_args = {
        .value = (uint64_t)(uintptr_t)&xattr_value,
        .size = 1,
    };
    errno = 0;
    if (syscall(SYS_setxattrat, AT_FDCWD, xattr_path, 0,
                xattr_name, &xattr_args, sizeof(xattr_args)) != -1 ||
        errno != EROFS) {
        return 541;
    }
    memset(&xattr_args, 0, sizeof(xattr_args));
    errno = 0;
    if (syscall(SYS_getxattrat, AT_FDCWD, xattr_path, 0,
                xattr_name, &xattr_args, sizeof(xattr_args)) != -1 ||
        errno != ENODATA) {
        return 542;
    }
    if (syscall(SYS_listxattrat, AT_FDCWD, xattr_path, 0,
                NULL, 0) != 0) {
        return 543;
    }
    errno = 0;
    if (syscall(SYS_removexattrat, AT_FDCWD, xattr_path, 0,
                xattr_name) != -1 ||
        errno != ENODATA) {
        return 544;
    }
    int xattrat_fd =
        syscall(SYS_open, xattr_path, O_RDONLY | O_CLOEXEC, 0);
    xattr_args.value = (uint64_t)(uintptr_t)&xattr_value;
    xattr_args.size = 1;
    if (xattrat_fd < 0 ||
        syscall(SYS_setxattrat, xattrat_fd, NULL, AT_EMPTY_PATH,
                xattr_name, &xattr_args,
                sizeof(xattr_args)) != -1 ||
        errno != EROFS ||
        close(xattrat_fd) != 0) {
        return 545;
    }
    struct sigaction protected_action = {.sa_handler = SIG_IGN};
    errno = 0;
    if (syscall(SYS_rt_sigaction, SIGKILL, &protected_action,
                NULL, 8) != -1 ||
        errno != EINVAL) {
        return 468;
    }
    errno = 0;
    if (kill(getpid(), SIGSTOP) != -1 || errno != EOPNOTSUPP) {
        return 469;
    }
    pid_t kill_child = fork();
    if (kill_child < 0) {
        return 470;
    }
    if (kill_child == 0) {
        pause();
        _exit(1);
    }
    int kill_status = 0;
    if (kill(kill_child, SIGKILL) != 0 ||
        waitpid(kill_child, &kill_status, 0) != kill_child) {
        return 471;
    }
    int mmsg_sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, mmsg_sockets) != 0) {
        return 472;
    }
    char mmsg_send_a[] = "one";
    char mmsg_send_b[] = "two";
    char mmsg_recv_a[4] = {0};
    char mmsg_recv_b[4] = {0};
    struct iovec mmsg_send_iov[2] = {
        {.iov_base = mmsg_send_a, .iov_len = 3},
        {.iov_base = mmsg_send_b, .iov_len = 3},
    };
    struct iovec mmsg_recv_iov[2] = {
        {.iov_base = mmsg_recv_a, .iov_len = 3},
        {.iov_base = mmsg_recv_b, .iov_len = 3},
    };
    struct mmsghdr mmsg_send[2] = {0};
    struct mmsghdr mmsg_recv[2] = {0};
    for (int message = 0; message < 2; message++) {
        mmsg_send[message].msg_hdr.msg_iov = &mmsg_send_iov[message];
        mmsg_send[message].msg_hdr.msg_iovlen = 1;
        mmsg_recv[message].msg_hdr.msg_iov = &mmsg_recv_iov[message];
        mmsg_recv[message].msg_hdr.msg_iovlen = 1;
    }
    if (syscall(SYS_sendmmsg, mmsg_sockets[0], mmsg_send, 2, 0) != 2 ||
        mmsg_send[0].msg_len != 3 || mmsg_send[1].msg_len != 3 ||
        syscall(SYS_recvmmsg, mmsg_sockets[1], mmsg_recv, 2,
                MSG_WAITFORONE, NULL) != 2 ||
        mmsg_recv[0].msg_len != 3 || mmsg_recv[1].msg_len != 3 ||
        memcmp(mmsg_recv_a, "one", 3) != 0 ||
        memcmp(mmsg_recv_b, "two", 3) != 0) {
        return 473;
    }
    struct timespec mmsg_timeout = {0};
    errno = 0;
    if (syscall(SYS_recvmmsg, mmsg_sockets[1], mmsg_recv, 1,
                0, &mmsg_timeout) != -1 ||
        errno != EOPNOTSUPP) {
        return 474;
    }
    errno = 0;
    if (syscall(SYS_sendmmsg, mmsg_sockets[0], mmsg_send, 17, 0) != -1 ||
        errno != EINVAL ||
        close(mmsg_sockets[0]) != 0 ||
        close(mmsg_sockets[1]) != 0) {
        return 475;
    }
    pid_t pidfd_child = fork();
    if (pidfd_child < 0) {
        return 476;
    }
    if (pidfd_child == 0) {
        pause();
        _exit(1);
    }
    int pidfd = syscall(SYS_pidfd_open, pidfd_child, 0x800);
    struct pollfd pidfd_poll = {
        .fd = pidfd,
        .events = POLLIN,
    };
    if (pidfd < 0 || poll(&pidfd_poll, 1, 0) != 0) {
        return 477;
    }
    errno = 0;
    if (syscall(SYS_pidfd_send_signal, pidfd, SIGTERM,
                (siginfo_t *)(uintptr_t)1, 0) != -1 ||
        errno != EOPNOTSUPP ||
        syscall(SYS_pidfd_send_signal, pidfd, SIGTERM, NULL, 0) != 0 ||
        poll(&pidfd_poll, 1, 1000) != 1 ||
        (pidfd_poll.revents & POLLIN) == 0 ||
        syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) != 0 ||
        waitpid(pidfd_child, NULL, 0) != pidfd_child ||
        close(pidfd) != 0) {
        return 478;
    }
    errno = 0;
    if (syscall(SYS_pidfd_open, getpid(), 1) != -1 ||
        errno != EINVAL) {
        return 479;
    }
    int self_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    int pidfd_source =
        syscall(SYS_open, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                O_RDONLY | O_CLOEXEC, 0);
    int pidfd_duplicate =
        self_pidfd < 0 || pidfd_source < 0
            ? -1
            : syscall(SYS_pidfd_getfd, self_pidfd, pidfd_source, 0);
    unsigned char pidfd_magic[4] = {0};
    if (pidfd_duplicate < 0 ||
        (fcntl(pidfd_duplicate, F_GETFD) & FD_CLOEXEC) == 0 ||
        read(pidfd_duplicate, pidfd_magic, sizeof(pidfd_magic)) !=
            (ssize_t)sizeof(pidfd_magic) ||
        memcmp(pidfd_magic, "\177ELF", 4) != 0) {
        return 510;
    }
    errno = 0;
    if (syscall(SYS_pidfd_getfd, self_pidfd, pidfd_source, 1) != -1 ||
        errno != EINVAL ||
        close(pidfd_duplicate) != 0 ||
        close(pidfd_source) != 0 ||
        close(self_pidfd) != 0) {
        return 511;
    }
    int inotify_fd =
        syscall(SYS_inotify_init1, IN_NONBLOCK | IN_CLOEXEC);
    int inotify_legacy_fd = syscall(SYS_inotify_init);
    if (inotify_fd < 0 || inotify_legacy_fd < 0 ||
        (fcntl(inotify_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        close(inotify_legacy_fd) != 0) {
        return 480;
    }
    int inotify_wd =
        syscall(SYS_inotify_add_watch, inotify_fd, xattr_path,
                IN_MODIFY | IN_ATTRIB);
    if (inotify_wd <= 0 ||
        syscall(SYS_inotify_add_watch, inotify_fd, xattr_path,
                IN_MODIFY | IN_MASK_ADD) != inotify_wd) {
        return 481;
    }
    char inotify_event[128];
    errno = 0;
    if (read(inotify_fd, inotify_event, sizeof(inotify_event)) != -1 ||
        errno != EAGAIN ||
        syscall(SYS_inotify_rm_watch, inotify_fd, inotify_wd) != 0) {
        return 482;
    }
    errno = 0;
    if (syscall(SYS_inotify_rm_watch, inotify_fd, inotify_wd) != -1 ||
        errno != EINVAL) {
        return 483;
    }
    errno = 0;
    if (syscall(SYS_inotify_add_watch, inotify_fd, "/missing-inotify",
                IN_MODIFY) != -1 ||
        errno != ENOENT ||
        close(inotify_fd) != 0) {
        return 485;
    }
    errno = 0;
    if (syscall(SYS_inotify_init1, 0x400000) != -1 ||
        errno != EINVAL) {
        return 484;
    }
    int copy_source =
        syscall(SYS_open, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                O_RDONLY | O_CLOEXEC, 0);
    int copy_target = memfd_create("copy-file-range", MFD_CLOEXEC);
    off_t copy_input_offset = 0;
    off_t copy_output_offset = 0;
    unsigned char copied_magic[8] = {0};
    if (copy_source < 0 || copy_target < 0 ||
        syscall(SYS_copy_file_range, copy_source, &copy_input_offset,
                copy_target, &copy_output_offset, 8, 0) != 8 ||
        copy_input_offset != 8 || copy_output_offset != 8 ||
        lseek(copy_target, 0, SEEK_SET) != 0 ||
        read(copy_target, copied_magic, sizeof(copied_magic)) !=
            (ssize_t)sizeof(copied_magic) ||
        memcmp(copied_magic, "\177ELF", 4) != 0) {
        return 486;
    }
    errno = 0;
    if (syscall(SYS_copy_file_range, copy_source, &copy_input_offset,
                copy_target, &copy_output_offset, 8, 1) != -1 ||
        errno != EINVAL ||
        close(copy_source) != 0 ||
        close(copy_target) != 0) {
        return 487;
    }
    if (syscall(SYS_setgroups, 0, NULL) != 0) {
        return 488;
    }
    gid_t supplementary_groups[2] = {7, 5};
    gid_t read_supplementary_groups[2] = {0};
    if (syscall(SYS_setgroups, 2, supplementary_groups) != 0 ||
        getgroups(0, NULL) != 2 ||
        getgroups(2, read_supplementary_groups) != 2 ||
        read_supplementary_groups[0] != 5 ||
        read_supplementary_groups[1] != 7) {
        return 489;
    }
    errno = 0;
    if (getgroups(1, read_supplementary_groups) != -1 ||
        errno != EINVAL ||
        syscall(SYS_setgroups, 0, NULL) != 0) {
        return 500;
    }
    struct __user_cap_header_struct capability_header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct capability_data[2] = {0};
    struct __user_cap_data_struct original_capability_data[2] = {0};
    if (syscall(SYS_capget, &capability_header, capability_data) != 0 ||
        (capability_data[0].effective == 0 &&
         capability_data[1].effective == 0)) {
        return 490;
    }
    memcpy(original_capability_data, capability_data,
           sizeof(original_capability_data));
    memset(capability_data, 0, sizeof(capability_data));
    capability_data[0].effective = 1;
    capability_data[0].permitted = 1;
    if (syscall(SYS_capset, &capability_header, capability_data) != 0 ||
        syscall(SYS_capget, &capability_header, capability_data) != 0 ||
        capability_data[0].effective != 1 ||
        capability_data[0].permitted != 1 ||
        capability_data[0].inheritable != 0) {
        return 491;
    }
    capability_data[0].effective = 3;
    capability_data[0].permitted = 1;
    errno = 0;
    if (syscall(SYS_capset, &capability_header, capability_data) != -1 ||
        errno != EPERM ||
        syscall(SYS_capset, &capability_header,
                original_capability_data) != 0) {
        return 492;
    }
    capability_header.version = 0;
    errno = 0;
    if (syscall(SYS_capget, &capability_header, capability_data) != -1 ||
        errno != EINVAL ||
        capability_header.version != _LINUX_CAPABILITY_VERSION_3) {
        return 493;
    }
    long initial_ioprio =
        syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0);
    if (initial_ioprio < 0 ||
        syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 5)) != 0 ||
        syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) !=
            IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 5) ||
        syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)) != 0 ||
        syscall(SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0) !=
            IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0)) {
        return 512;
    }
    errno = 0;
    if (syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 8)) != -1 ||
        errno != EINVAL ||
        syscall(SYS_ioprio_get, IOPRIO_WHO_PGRP, 0) != -1 ||
        errno != EOPNOTSUPP ||
        syscall(SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0,
                (unsigned)initial_ioprio) != 0) {
        return 513;
    }
    uid_t credential_real_uid = 0;
    uid_t credential_effective_uid = 0;
    uid_t credential_saved_uid = 0;
    gid_t credential_real_gid = 0;
    gid_t credential_effective_gid = 0;
    gid_t credential_saved_gid = 0;
    if (getresuid(&credential_real_uid, &credential_effective_uid,
                  &credential_saved_uid) != 0 ||
        getresgid(&credential_real_gid, &credential_effective_gid,
                  &credential_saved_gid) != 0 ||
        credential_real_uid != 0 || credential_effective_uid != 0 ||
        credential_saved_uid != 0 || credential_real_gid != 0 ||
        credential_effective_gid != 0 || credential_saved_gid != 0 ||
        syscall(SYS_setfsuid, 123) != 0 ||
        syscall(SYS_setfsuid, 0) != 123 ||
        syscall(SYS_setfsgid, 124) != 0 ||
        syscall(SYS_setfsgid, 0) != 124) {
        return 494;
    }
    if (syscall(SYS_setresuid, 100, 100, 0) != 0 ||
        getresuid(&credential_real_uid, &credential_effective_uid,
                  &credential_saved_uid) != 0 ||
        credential_real_uid != 100 || credential_effective_uid != 100 ||
        credential_saved_uid != 0) {
        return 495;
    }
    errno = 0;
    if (syscall(SYS_setuid, 200) != -1 || errno != EPERM ||
        syscall(SYS_setresuid, 0, 0, 0) != 0 ||
        getuid() != 0 || geteuid() != 0) {
        return 496;
    }
    if (syscall(SYS_setresgid, 110, 110, 0) != 0 ||
        getresgid(&credential_real_gid, &credential_effective_gid,
                  &credential_saved_gid) != 0 ||
        credential_real_gid != 110 || credential_effective_gid != 110 ||
        credential_saved_gid != 0 ||
        syscall(SYS_setresgid, 0, 0, 0) != 0 ||
        getgid() != 0 || getegid() != 0) {
        return 497;
    }
    pid_t credentials_child = fork();
    if (credentials_child < 0) {
        return 498;
    }
    if (credentials_child == 0) {
        int ok = syscall(SYS_setreuid, 101, 101) == 0 &&
                 getuid() == 101 && geteuid() == 101 &&
                 syscall(SYS_setregid, 102, 102) == 0 &&
                 getgid() == 102 && getegid() == 102;
        _exit(ok ? 0 : 1);
    }
    int credentials_status = 0;
    if (waitpid(credentials_child, &credentials_status, 0) !=
            credentials_child ||
        !WIFEXITED(credentials_status) ||
        WEXITSTATUS(credentials_status) != 0 ||
        getuid() != 0 || getgid() != 0) {
        return 499;
    }
    mode_t old_umask = umask(077);
    if (old_umask != 022 || umask(old_umask) != 077) {
        return 501;
    }
    int umask_msg = msgget(0x554d5347, IPC_CREAT | IPC_EXCL | 0666);
    int umask_sem = semget(0x554d5345, 1, IPC_CREAT | IPC_EXCL | 0666);
    int umask_shm = shmget(0x554d5348, 4096,
                           IPC_CREAT | IPC_EXCL | 0666);
    struct msqid_ds umask_msg_status = {0};
    struct semid_ds umask_sem_status = {0};
    struct shmid_ds umask_shm_status = {0};
    if (umask_msg < 0 || umask_sem < 0 || umask_shm < 0 ||
        msgctl(umask_msg, IPC_STAT, &umask_msg_status) != 0 ||
        (umask_msg_status.msg_perm.mode & 0777) != 0600 ||
        syscall(SYS_semctl, umask_sem, IPC_STAT, 0,
                &umask_sem_status) != 0 ||
        (umask_sem_status.sem_perm.mode & 0777) != 0600 ||
        shmctl(umask_shm, IPC_STAT, &umask_shm_status) != 0 ||
        (umask_shm_status.shm_perm.mode & 0777) != 0600 ||
        msgctl(umask_msg, IPC_RMID, NULL) != 0 ||
        syscall(SYS_semctl, umask_sem, IPC_RMID, 0, 0) != 0 ||
        shmctl(umask_shm, IPC_RMID, NULL) != 0 ||
        umask(022) != 077) {
        return 695;
    }
    const char *mutable_parent = "/usr/lib/x86_64-linux-gnu";
    const char *new_vfs_path = "/usr/lib/x86_64-linux-gnu/jasper-new-node";
    errno = 0;
    if (syscall(SYS_mkdir, mutable_parent, 0755) != -1 ||
        errno != EEXIST ||
        syscall(SYS_mkdir, new_vfs_path, 0755) != -1 ||
        errno != EROFS) {
        return 502;
    }
    errno = 0;
    if (syscall(SYS_mkdirat, AT_FDCWD, new_vfs_path, 0755) != -1 ||
        errno != EROFS) {
        return 503;
    }
    errno = 0;
    if (syscall(SYS_mknod, mutable_parent, S_IFREG | 0600, 0) != -1 ||
        errno != EEXIST ||
        syscall(SYS_mknod, new_vfs_path, S_IFREG | 0600, 0) != -1 ||
        errno != EROFS ||
        syscall(SYS_mknodat, AT_FDCWD, new_vfs_path,
                S_IFREG | 0600, 0) != -1 ||
        errno != EROFS) {
        return 504;
    }
    errno = 0;
    if (syscall(SYS_unlink, xattr_path) != -1 || errno != EROFS ||
        syscall(SYS_unlink, "/usr") != -1 || errno != EISDIR ||
        syscall(SYS_unlinkat, AT_FDCWD, xattr_path, 0) != -1 ||
        errno != EROFS ||
        syscall(SYS_unlinkat, AT_FDCWD, xattr_path, AT_REMOVEDIR) != -1 ||
        errno != ENOTDIR) {
        return 505;
    }
    errno = 0;
    if (syscall(SYS_rmdir, xattr_path) != -1 || errno != ENOTDIR ||
        syscall(SYS_rmdir, "/usr") != -1 || errno != EROFS) {
        return 506;
    }
    errno = 0;
    if (syscall(SYS_rename, xattr_path, new_vfs_path) != -1 ||
        errno != EROFS ||
        syscall(SYS_renameat, AT_FDCWD, xattr_path,
                AT_FDCWD, new_vfs_path) != -1 ||
        errno != EROFS ||
        syscall(SYS_renameat2, AT_FDCWD, xattr_path,
                AT_FDCWD, new_vfs_path, 1) != -1 ||
        errno != EOPNOTSUPP) {
        return 507;
    }
    errno = 0;
    if (syscall(SYS_link, xattr_path, new_vfs_path) != -1 ||
        errno != EROFS ||
        syscall(SYS_linkat, AT_FDCWD, xattr_path,
                AT_FDCWD, new_vfs_path, 0) != -1 ||
        errno != EROFS ||
        syscall(SYS_symlink, "target", new_vfs_path) != -1 ||
        errno != EROFS ||
        syscall(SYS_symlinkat, "target", AT_FDCWD,
                new_vfs_path) != -1 ||
        errno != EROFS) {
        return 508;
    }
    const long privileged_calls[] = {
        SYS_mount, SYS_umount2, SYS_pivot_root, SYS_chroot,
        SYS_swapon, SYS_swapoff, SYS_init_module, SYS_finit_module,
        SYS_delete_module, SYS_acct, SYS_iopl, SYS_ioperm,
        SYS_kexec_load, SYS_kexec_file_load, SYS_quotactl,
        SYS_quotactl_fd, SYS_bpf, SYS_perf_event_open, SYS_ptrace,
        SYS_setns, SYS_unshare, SYS_syslog,
    };
    for (size_t index = 0;
         index < sizeof(privileged_calls) / sizeof(privileged_calls[0]);
         index++) {
        errno = 0;
        if (syscall(privileged_calls[index], 0, 0, 0, 0, 0, 0) != -1 ||
            errno != EPERM) {
            printf("privileged-call-fail nr=%ld errno=%d\n",
                   privileged_calls[index], errno);
            return 509;
        }
    }
    char process_vm_source[] = "VMIO";
    char process_vm_copy[5] = {0};
    char process_vm_write[] = "SEND";
    char process_vm_destination[5] = {0};
    struct iovec process_vm_local = {
        .iov_base = process_vm_copy,
        .iov_len = 4,
    };
    struct iovec process_vm_remote = {
        .iov_base = process_vm_source,
        .iov_len = 4,
    };
    if (syscall(SYS_process_vm_readv, getpid(), &process_vm_local, 1,
                &process_vm_remote, 1, 0) != 4 ||
        memcmp(process_vm_copy, "VMIO", 4) != 0) {
        return 514;
    }
    process_vm_local.iov_base = process_vm_write;
    process_vm_remote.iov_base = process_vm_destination;
    if (syscall(SYS_process_vm_writev, getpid(), &process_vm_local, 1,
                &process_vm_remote, 1, 0) != 4 ||
        memcmp(process_vm_destination, "SEND", 4) != 0) {
        return 515;
    }
    errno = 0;
    if (syscall(SYS_process_vm_readv, getpid(), &process_vm_local, 1,
                &process_vm_remote, 1, 1) != -1 ||
        errno != EINVAL ||
        syscall(SYS_process_vm_writev, getpid(),
                (struct iovec *)(uintptr_t)1, 1,
                &process_vm_remote, 1, 0) != -1 ||
        errno != EFAULT) {
        return 516;
    }
    int splice_source_pipe[2];
    int splice_dest_pipe[2];
    char splice_readback[8] = {0};
    if (pipe(splice_source_pipe) != 0 || pipe(splice_dest_pipe) != 0 ||
        write(splice_source_pipe[1], "splice", 6) != 6 ||
        syscall(SYS_splice, splice_source_pipe[0], NULL,
                splice_dest_pipe[1], NULL, 6, 0) != 6 ||
        read(splice_dest_pipe[0], splice_readback, 6) != 6 ||
        memcmp(splice_readback, "splice", 6) != 0) {
        return 517;
    }
    int splice_file =
        syscall(SYS_open, "/usr/lib/x86_64-linux-gnu/libc.so.6",
                O_RDONLY | O_CLOEXEC, 0);
    off_t splice_offset = 0;
    memset(splice_readback, 0, sizeof(splice_readback));
    if (splice_file < 0 ||
        syscall(SYS_splice, splice_file, &splice_offset,
                splice_source_pipe[1], NULL, 4, 0) != 4 ||
        splice_offset != 4 ||
        read(splice_source_pipe[0], splice_readback, 4) != 4 ||
        memcmp(splice_readback, "\177ELF", 4) != 0) {
        return 518;
    }
    errno = 0;
    if (syscall(SYS_splice, splice_file, &splice_offset,
                splice_source_pipe[1], NULL, 4, 0x10) != -1 ||
        errno != EINVAL ||
        close(splice_file) != 0 ||
        close(splice_source_pipe[0]) != 0 ||
        close(splice_source_pipe[1]) != 0 ||
        close(splice_dest_pipe[0]) != 0 ||
        close(splice_dest_pipe[1]) != 0) {
        return 519;
    }
    int vmsplice_pipe[2];
    char vmsplice_first[] = "vm";
    char vmsplice_second[] = "spl";
    char vmsplice_readback[6] = {0};
    struct iovec vmsplice_vectors[2] = {
        {.iov_base = vmsplice_first, .iov_len = 2},
        {.iov_base = vmsplice_second, .iov_len = 3},
    };
    if (pipe(vmsplice_pipe) != 0 ||
        syscall(SYS_vmsplice, vmsplice_pipe[1], vmsplice_vectors,
                2, 0) != 5 ||
        read(vmsplice_pipe[0], vmsplice_readback, 5) != 5 ||
        memcmp(vmsplice_readback, "vmspl", 5) != 0) {
        return 520;
    }
    errno = 0;
    if (syscall(SYS_vmsplice, vmsplice_pipe[1], vmsplice_vectors,
                2, 0x10) != -1 ||
        errno != EINVAL ||
        syscall(SYS_vmsplice, vmsplice_pipe[0], vmsplice_vectors,
                2, 0) != -1 ||
        errno != EBADF ||
        close(vmsplice_pipe[0]) != 0 ||
        close(vmsplice_pipe[1]) != 0) {
        return 521;
    }
    int tee_source[2];
    int tee_destination[2];
    char tee_source_data[8] = {0};
    char tee_destination_data[8] = {0};
    if (pipe(tee_source) != 0 || pipe(tee_destination) != 0 ||
        write(tee_source[1], "teedata", 8) != 8 ||
        syscall(SYS_tee, tee_source[0], tee_destination[1], 8, 0) != 8 ||
        read(tee_source[0], tee_source_data, 8) != 8 ||
        read(tee_destination[0], tee_destination_data, 8) != 8 ||
        memcmp(tee_source_data, "teedata", 8) != 0 ||
        memcmp(tee_destination_data, "teedata", 8) != 0) {
        return 532;
    }
    errno = 0;
    if (syscall(SYS_tee, tee_source[0], tee_destination[1], 8, 0x10) != -1 ||
        errno != EINVAL ||
        syscall(SYS_tee, tee_source[1], tee_destination[1], 8, 0) != -1 ||
        errno != EBADF ||
        close(tee_source[0]) != 0 ||
        close(tee_source[1]) != 0 ||
        close(tee_destination[0]) != 0 ||
        close(tee_destination[1]) != 0) {
        return 533;
    }
    void *sealed_memory =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *unsealed_memory =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (sealed_memory == MAP_FAILED || unsealed_memory == MAP_FAILED ||
        syscall(SYS_mseal, sealed_memory, 4096, 0) != 0) {
        return 522;
    }
    errno = 0;
    if (mprotect(sealed_memory, 4096, PROT_READ) != -1 ||
        errno != EPERM ||
        munmap(sealed_memory, 4096) != -1 || errno != EPERM ||
        (void *)syscall(SYS_mremap, sealed_memory, 4096, 4096,
                        MREMAP_MAYMOVE, NULL) != MAP_FAILED ||
        errno != EPERM ||
        madvise(sealed_memory, 4096, MADV_DONTNEED) != -1 ||
        errno != EPERM) {
        return 523;
    }
    errno = 0;
    if (syscall(SYS_mseal, unsealed_memory, 4096, 1) != -1 ||
        errno != EINVAL ||
        munmap(unsealed_memory, 4096) != 0) {
        return 524;
    }
    long membarrier_commands =
        syscall(SYS_membarrier, MEMBARRIER_CMD_QUERY, 0, 0);
    if ((membarrier_commands & MEMBARRIER_CMD_PRIVATE_EXPEDITED) == 0 ||
        (membarrier_commands & MEMBARRIER_CMD_GLOBAL) == 0 ||
        syscall(SYS_membarrier,
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED, 0, 0) != 0 ||
        syscall(SYS_membarrier,
                MEMBARRIER_CMD_PRIVATE_EXPEDITED, 0, 0) != 0 ||
        syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 0, 0) != 0) {
        return 525;
    }
    errno = 0;
    if (syscall(SYS_membarrier, 0x40000000, 0, 0) != -1 ||
        errno != EOPNOTSUPP ||
        syscall(SYS_membarrier, MEMBARRIER_CMD_GLOBAL, 1, 0) != -1 ||
        errno != EINVAL) {
        return 526;
    }
    if (syscall(SYS_personality, 0xffffffffUL) != 0 ||
        syscall(SYS_personality, 0) != 0) {
        return 527;
    }
    errno = 0;
    if (syscall(SYS_personality, 1) != -1 || errno != EINVAL ||
        syscall(SYS_restart_syscall) != -1 || errno != EINTR ||
        syscall(SYS_remap_file_pages, NULL, 4096, 0, 0, 0) != -1 ||
        errno != EOPNOTSUPP ||
        syscall(SYS_vhangup) != -1 || errno != EPERM) {
        return 528;
    }
    const long legacy_calls[] = {
        SYS_get_thread_area, SYS_set_thread_area, SYS_modify_ldt, SYS__sysctl,
        SYS_afs_syscall, SYS_create_module, SYS_get_kernel_syms,
        SYS_query_module, SYS_nfsservctl, SYS_getpmsg, SYS_putpmsg,
        SYS_tuxcall, SYS_vserver, SYS_security, SYS_ustat, SYS_uselib,
        SYS_sysfs,
    };
    for (size_t index = 0;
         index < sizeof(legacy_calls) / sizeof(legacy_calls[0]); index++) {
        errno = 0;
        if (syscall(legacy_calls[index], 0, 0, 0, 0, 0, 0) != -1 ||
            errno != ENOSYS) {
            printf("legacy-call-fail nr=%ld errno=%d\n",
                   legacy_calls[index], errno);
            return 529;
        }
    }
    if (syscall(SYS_rseq_slice_yield) != 0) {
        return 534;
    }
    errno = 0;
    if (syscall(SYS_lookup_dcookie, 0, NULL, 0) != -1 ||
        errno != ENOENT) {
        return 535;
    }
    unsigned long shstk_features = ARCH_SHSTK_SHSTK;
    if (prctl(ARCH_SHSTK_STATUS, &shstk_features, 0, 0, 0) != 0 ||
        shstk_features != 0 ||
        prctl(ARCH_SHSTK_LOCK, ARCH_SHSTK_SHSTK | ARCH_SHSTK_WRSS,
              0, 0, 0) != 0) {
        return 652;
    }
    const long unsupported_features[] = {
        SYS_fanotify_init, SYS_fanotify_mark,
        SYS_lsm_set_self_attr,
        SYS_map_shadow_stack,
        SYS_uprobe, SYS_uretprobe, SYS_userfaultfd,
    };
    for (size_t index = 0;
         index < sizeof(unsupported_features) / sizeof(unsupported_features[0]);
         index++) {
        errno = 0;
        if (syscall(unsupported_features[index], 0, 0, 0, 0, 0, 0) != -1 ||
            errno != EOPNOTSUPP) {
            printf("unsupported-feature-fail nr=%ld errno=%d\n",
                   unsupported_features[index], errno);
            return 536;
        }
    }
    if (syscall(SYS_landlock_create_ruleset, NULL, 0,
                LANDLOCK_CREATE_RULESET_VERSION) != 4) {
        return 692;
    }
    pid_t landlock_child = fork();
    if (landlock_child < 0) {
        return 693;
    }
    if (landlock_child == 0) {
        struct landlock_ruleset_attr ruleset_attr = {
            .handled_access_fs =
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_EXECUTE,
        };
        int usr_ruleset = syscall(SYS_landlock_create_ruleset,
                                  &ruleset_attr,
                                  sizeof(ruleset_attr), 0);
        int usr_dir = open("/usr", O_PATH | O_DIRECTORY | O_CLOEXEC);
        struct landlock_path_beneath_attr usr_rule = {
            .allowed_access =
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_EXECUTE,
            .parent_fd = usr_dir,
        };
        if (usr_ruleset < 0 || usr_dir < 0 ||
            (fcntl(usr_ruleset, F_GETFD) & FD_CLOEXEC) == 0 ||
            syscall(SYS_landlock_add_rule, usr_ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &usr_rule, 0) != 0) {
            _exit(1);
        }
        atomic_store(&landlock_worker_stage, 0);
        atomic_store(&landlock_worker_first_done, 0);
        atomic_store(&landlock_worker_second_done, 0);
        pthread_t landlock_thread;
        if (pthread_create(&landlock_thread, NULL,
                           landlock_worker, NULL) != 0) {
            _exit(2);
        }
        errno = 0;
        if (syscall(SYS_landlock_add_rule, usr_ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &usr_rule, 0) != -1 || errno != EEXIST ||
            syscall(SYS_landlock_restrict_self,
                    usr_ruleset, 0) != -1 || errno != EPERM ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            syscall(SYS_landlock_restrict_self,
                    usr_ruleset, 0) != 0) {
            _exit(3);
        }
        int allowed = open("/usr/lib/x86_64-linux-gnu/libc.so.6",
                           O_RDONLY | O_CLOEXEC);
        errno = 0;
        int denied = open("/lib/x86_64-linux-gnu/libc.so.6",
                          O_RDONLY | O_CLOEXEC);
        int path_only = open("/lib/x86_64-linux-gnu/libc.so.6",
                             O_PATH | O_CLOEXEC);
        if (allowed < 0 || denied != -1 || errno != EACCES ||
            path_only < 0) {
            _exit(4);
        }
        close(allowed);
        close(path_only);
        for (int spin = 0;
             spin < 10000 &&
             !atomic_load_explicit(&landlock_worker_first_done,
                                   memory_order_acquire);
             spin++) {
            sched_yield();
        }
        if (!atomic_load_explicit(&landlock_worker_first_done,
                                  memory_order_acquire) ||
            !atomic_load_explicit(&landlock_worker_first_ok,
                                  memory_order_acquire) ||
            syscall(SYS_landlock_restrict_self, usr_ruleset,
                    LANDLOCK_RESTRICT_SELF_TSYNC) != 0) {
            _exit(5);
        }
        atomic_store_explicit(&landlock_worker_stage, 1,
                              memory_order_release);
        for (int spin = 0;
             spin < 10000 &&
             !atomic_load_explicit(&landlock_worker_second_done,
                                   memory_order_acquire);
             spin++) {
            sched_yield();
        }
        if (!atomic_load_explicit(&landlock_worker_second_done,
                                  memory_order_acquire) ||
            !atomic_load_explicit(&landlock_worker_second_ok,
                                  memory_order_acquire) ||
            pthread_join(landlock_thread, NULL) != 0) {
            _exit(6);
        }
        pid_t sandbox_fork = fork();
        if (sandbox_fork < 0) {
            _exit(7);
        }
        if (sandbox_fork == 0) {
            int inherited_allowed =
                open("/usr/lib/x86_64-linux-gnu/libc.so.6",
                     O_RDONLY | O_CLOEXEC);
            errno = 0;
            int inherited_denied =
                open("/lib/x86_64-linux-gnu/libc.so.6",
                     O_RDONLY | O_CLOEXEC);
            _exit(inherited_allowed >= 0 &&
                          inherited_denied == -1 && errno == EACCES
                      ? 0
                      : 1);
        }
        int sandbox_fork_status = 0;
        if (waitpid(sandbox_fork, &sandbox_fork_status, 0) !=
                sandbox_fork ||
            !WIFEXITED(sandbox_fork_status) ||
            WEXITSTATUS(sandbox_fork_status) != 0) {
            _exit(8);
        }
        int lib_ruleset = syscall(SYS_landlock_create_ruleset,
                                  &ruleset_attr,
                                  sizeof(ruleset_attr), 0);
        int lib_dir = open("/lib", O_PATH | O_DIRECTORY | O_CLOEXEC);
        struct landlock_path_beneath_attr lib_rule = {
            .allowed_access =
                LANDLOCK_ACCESS_FS_READ_FILE |
                LANDLOCK_ACCESS_FS_EXECUTE,
            .parent_fd = lib_dir,
        };
        if (lib_ruleset < 0 || lib_dir < 0 ||
            syscall(SYS_landlock_add_rule, lib_ruleset,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &lib_rule, 0) != 0 ||
            syscall(SYS_landlock_restrict_self,
                    lib_ruleset, 0) != 0) {
            _exit(9);
        }
        errno = 0;
        int usr_after_stack =
            open("/usr/lib/x86_64-linux-gnu/libc.so.6",
                 O_RDONLY | O_CLOEXEC);
        int usr_stack_errno = errno;
        errno = 0;
        int lib_after_stack =
            open("/lib/x86_64-linux-gnu/libc.so.6",
                 O_RDONLY | O_CLOEXEC);
        int lib_stack_errno = errno;
        _exit(usr_after_stack == -1 && usr_stack_errno == EACCES &&
                      lib_after_stack == -1 && lib_stack_errno == EACCES
                  ? 0
                  : 10);
    }
    int landlock_status = 0;
    if (waitpid(landlock_child, &landlock_status, 0) != landlock_child ||
        !WIFEXITED(landlock_status) ||
        WEXITSTATUS(landlock_status) != 0) {
        return 694;
    }
    int secret_fd = syscall(SYS_memfd_secret, O_CLOEXEC);
    char secret_readback[6] = {0};
    if (secret_fd < 0 ||
        (fcntl(secret_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        write(secret_fd, "secret", 6) != 6 ||
        lseek(secret_fd, 0, SEEK_SET) != 0 ||
        read(secret_fd, secret_readback, 6) != 6 ||
        memcmp(secret_readback, "secret", 6) != 0 ||
        close(secret_fd) != 0) {
        return 530;
    }
    errno = 0;
    if (syscall(SYS_memfd_secret, 1) != -1 || errno != EINVAL) {
        return 531;
    }
    int aio_fd = memfd_create("legacy-aio", MFD_CLOEXEC);
    unsigned long aio_context = 0;
    char aio_source[] = "aio!";
    char aio_result[4] = {0};
    char aio_write_data[] = "done";
    char aio_written[4] = {0};
    if (aio_fd < 0 ||
        write(aio_fd, aio_source, sizeof(aio_source) - 1) != 4 ||
        syscall(SYS_io_setup, 4, &aio_context) != 0) {
        return 537;
    }
    struct iocb aio_read = {
        .aio_data = 0x41494f52454144ULL,
        .aio_lio_opcode = IOCB_CMD_PREAD,
        .aio_fildes = aio_fd,
        .aio_buf = (uint64_t)(uintptr_t)aio_result,
        .aio_nbytes = sizeof(aio_result),
        .aio_offset = 0,
    };
    struct iocb *aio_read_pointer = &aio_read;
    struct io_event aio_event = {0};
    struct timespec aio_timeout = {.tv_sec = 1};
    if (syscall(SYS_io_submit, aio_context, 1, &aio_read_pointer) != 1 ||
        syscall(SYS_io_getevents, aio_context, 1, 1,
                &aio_event, &aio_timeout) != 1 ||
        aio_event.data != aio_read.aio_data ||
        aio_event.obj != (uint64_t)(uintptr_t)&aio_read ||
        aio_event.res != 4 ||
        memcmp(aio_result, "aio!", 4) != 0) {
        return 538;
    }
    struct iocb aio_write = {
        .aio_data = 0x41494f5752495445ULL,
        .aio_lio_opcode = IOCB_CMD_PWRITE,
        .aio_fildes = aio_fd,
        .aio_buf = (uint64_t)(uintptr_t)aio_write_data,
        .aio_nbytes = sizeof(aio_write_data) - 1,
        .aio_offset = 4,
    };
    struct iocb *aio_write_pointer = &aio_write;
    memset(&aio_event, 0, sizeof(aio_event));
    if (syscall(SYS_io_submit, aio_context, 1, &aio_write_pointer) != 1 ||
        syscall(SYS_io_getevents, aio_context, 1, 1,
                &aio_event, &aio_timeout) != 1 ||
        aio_event.res != 4 ||
        pread(aio_fd, aio_written, sizeof(aio_written), 4) != 4 ||
        memcmp(aio_written, "done", 4) != 0) {
        return 539;
    }
    errno = 0;
    if (syscall(SYS_io_cancel, aio_context, &aio_write,
                &aio_event) != -1 ||
        errno != EINVAL ||
        syscall(SYS_io_destroy, aio_context) != 0 ||
        syscall(SYS_io_getevents, aio_context, 0, 1,
                &aio_event, NULL) != -1 ||
        errno != EINVAL ||
        close(aio_fd) != 0) {
        return 540;
    }
    futex2_word = 0;
    atomic_store_explicit(&futex2_started, 0, memory_order_relaxed);
    atomic_store_explicit(&futex2_finished, 0, memory_order_relaxed);
    pthread_t futex2_thread;
    if (pthread_create(&futex2_thread, NULL, futex2_waiter, NULL) != 0) {
        return 546;
    }
    while (!atomic_load_explicit(&futex2_started, memory_order_acquire)) {
        sched_yield();
    }
    struct timespec futex2_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    nanosleep(&futex2_delay, NULL);
    __atomic_store_n(&futex2_word, 1, __ATOMIC_RELEASE);
    if (syscall(SYS_futex_wake, &futex2_word, UINT32_MAX, 1,
                FUTEX2_SIZE_U32 | FUTEX2_PRIVATE) != 1) {
        return 547;
    }
    void *futex2_thread_result = NULL;
    if (pthread_join(futex2_thread, &futex2_thread_result) != 0 ||
        futex2_thread_result != NULL ||
        !atomic_load_explicit(&futex2_finished, memory_order_acquire)) {
        return 548;
    }
    struct futex2_waitv_probe futex2_waitv[2] = {
        {
            .value = 1,
            .address = (uint64_t)(uintptr_t)&futex2_word,
            .flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        },
        {
            .value = 1,
            .address = (uint64_t)(uintptr_t)&futex2_destination,
            .flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        },
    };
    if (syscall(SYS_futex_waitv, futex2_waitv, 2, 0,
                NULL, CLOCK_MONOTONIC) != 1) {
        return 549;
    }
    futex2_destination = 0;
    struct futex2_waitv_probe futex2_requeue[2] = {
        {
            .value = 1,
            .address = (uint64_t)(uintptr_t)&futex2_word,
            .flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        },
        {
            .value = 0,
            .address = (uint64_t)(uintptr_t)&futex2_destination,
            .flags = FUTEX2_SIZE_U32 | FUTEX2_PRIVATE,
        },
    };
    if (syscall(SYS_futex_requeue, futex2_requeue, 0, 0, 1) != 0) {
        return 550;
    }
    errno = 0;
    if (syscall(SYS_futex_wake, &futex2_word, 0, 1,
                FUTEX2_SIZE_U32) != -1 ||
        errno != EINVAL) {
        return 551;
    }
    const char *mq_name = "jasper-mq-test";
    syscall(SYS_mq_unlink, mq_name);
    struct mq_attr mq_attributes = {
        .mq_maxmsg = 4,
        .mq_msgsize = 64,
    };
    int mq_fd = syscall(SYS_mq_open, mq_name,
                        O_CREAT | O_RDWR | O_NONBLOCK,
                        0600, &mq_attributes);
    struct mq_attr mq_current = {0};
    char mq_first[64] = {0};
    char mq_second[64] = {0};
    unsigned mq_priority = 0;
    if (mq_fd < 0 ||
        (fcntl(mq_fd, F_GETFD) & FD_CLOEXEC) == 0 ||
        syscall(SYS_mq_getsetattr, mq_fd, NULL, &mq_current) != 0 ||
        mq_current.mq_maxmsg != 4 || mq_current.mq_msgsize != 64 ||
        (mq_current.mq_flags & O_NONBLOCK) == 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "low", 3, 1, NULL) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "high", 4, 5, NULL) != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), &mq_priority, NULL) != 4 ||
        mq_priority != 5 || memcmp(mq_first, "high", 4) != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_second,
                sizeof(mq_second), &mq_priority, NULL) != 3 ||
        mq_priority != 1 || memcmp(mq_second, "low", 3) != 0) {
        return 552;
    }
    struct mq_attr mq_change = {0};
    struct mq_attr mq_previous = {0};
    char mq_too_large[65] = {0};
    if (syscall(SYS_mq_getsetattr, mq_fd, &mq_change, &mq_previous) != 0 ||
        (mq_previous.mq_flags & O_NONBLOCK) == 0 ||
        syscall(SYS_mq_timedsend, mq_fd, mq_too_large,
                sizeof(mq_too_large), 0, NULL) != -1 ||
        errno != EMSGSIZE ||
        syscall(SYS_mq_timedsend, mq_fd, "bad", 3, 32768, NULL) != -1 ||
        errno != EINVAL ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first, 32, NULL, NULL) != -1 ||
        errno != EMSGSIZE ||
        syscall(SYS_mq_open, mq_name, O_CREAT | O_EXCL | O_RDWR,
                0600, NULL) != -1 || errno != EEXIST) {
        return 555;
    }
    mq_change.mq_flags = O_NONBLOCK;
    if (syscall(SYS_mq_getsetattr, mq_fd, &mq_change, NULL) != 0) {
        return 654;
    }
    struct pollfd mq_poll = {
        .fd = mq_fd,
        .events = POLLIN | POLLOUT,
    };
    int mq_epfd = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event mq_interest = {
        .events = EPOLLIN | EPOLLOUT,
        .data.u64 = 0x4d51504f4c4cULL,
    };
    struct epoll_event mq_ready = {0};
    if (mq_epfd < 0 ||
        epoll_ctl(mq_epfd, EPOLL_CTL_ADD, mq_fd, &mq_interest) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "poll", 4, 0, NULL) != 0 ||
        poll(&mq_poll, 1, 1000) != 1 ||
        (mq_poll.revents & (POLLIN | POLLOUT)) !=
            (POLLIN | POLLOUT) ||
        epoll_wait(mq_epfd, &mq_ready, 1, 1000) != 1 ||
        (mq_ready.events & (EPOLLIN | EPOLLOUT)) !=
            (EPOLLIN | EPOLLOUT) ||
        mq_ready.data.u64 != 0x4d51504f4c4cULL ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "poll", 4) != 0 ||
        epoll_ctl(mq_epfd, EPOLL_CTL_DEL, mq_fd, NULL) != 0 ||
        close(mq_epfd) != 0) {
        return 655;
    }
    struct sigevent mq_none_event = {.sigev_notify = SIGEV_NONE};
    if (syscall(SYS_mq_notify, mq_fd, &mq_none_event) != 0) {
        return 656;
    }
    errno = 0;
    if (syscall(SYS_mq_notify, mq_fd, &mq_none_event) != -1 ||
        errno != EBUSY) {
        return 657;
    }
    if (syscall(SYS_mq_timedsend, mq_fd, "none", 4, 0, NULL) != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "none", 4) != 0 ||
        syscall(SYS_mq_notify, mq_fd, &mq_none_event) != 0 ||
        syscall(SYS_mq_notify, mq_fd, NULL) != 0) {
        return 658;
    }
    errno = 0;
    if (syscall(SYS_mq_notify, mq_fd, NULL) != -1 || errno != EINVAL) {
        return 659;
    }
    struct sigevent mq_bad_event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = 0,
    };
    errno = 0;
    if (syscall(SYS_mq_notify, mq_fd, (void *)1) != -1 ||
        errno != EFAULT ||
        syscall(SYS_mq_notify, mq_fd, &mq_bad_event) != -1 ||
        errno != EINVAL) {
        return 666;
    }
    struct sigaction mq_action = {0};
    struct sigaction mq_previous_action;
    mq_action.sa_sigaction = mq_notification_handler;
    mq_action.sa_flags = SA_SIGINFO;
    sigemptyset(&mq_action.sa_mask);
    sigset_t mq_signal_set;
    sigset_t mq_previous_mask;
    sigemptyset(&mq_signal_set);
    sigaddset(&mq_signal_set, SIGUSR1);
    struct sigevent mq_signal_event = {
        .sigev_notify = SIGEV_SIGNAL,
        .sigev_signo = SIGUSR1,
        .sigev_value.sival_int = 0x4d514e4f,
    };
    if (sigaction(SIGUSR1, &mq_action, &mq_previous_action) != 0 ||
        sigprocmask(SIG_UNBLOCK, &mq_signal_set, &mq_previous_mask) != 0) {
        return 660;
    }
    mq_notification_signals = 0;
    if (syscall(SYS_mq_notify, mq_fd, &mq_signal_event) != 0) {
        return 661;
    }
    if (syscall(SYS_mq_timedsend, mq_fd, "held", 4, 0, NULL) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "wait", 4, 0, NULL) != 0) {
        return 662;
    }
    for (int attempt = 0; attempt < 8 && mq_notification_signals == 0;
         attempt++) {
        syscall(SYS_getpid);
    }
    if (mq_notification_signals != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "held", 4) != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "wait", 4) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "note", 4, 0, NULL) != 0) {
        return 663;
    }
    for (int attempt = 0; attempt < 8 && mq_notification_signals == 0;
         attempt++) {
        syscall(SYS_getpid);
    }
    if (mq_notification_signals != 1 ||
        mq_notification_pid != getpid() ||
        mq_notification_uid != getuid() ||
        mq_notification_code != SI_MESGQ ||
        (uint32_t)mq_notification_value != 0x4d514e4f ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "note", 4) != 0) {
        return 664;
    }
    int mq_wait_started[2];
    int mq_wait_done[2];
    if (pipe(mq_wait_started) != 0 || pipe(mq_wait_done) != 0) {
        return 676;
    }
    mq_notification_signals = 0;
    if (syscall(SYS_mq_notify, mq_fd, &mq_signal_event) != 0) {
        return 677;
    }
    pid_t mq_waiter = fork();
    if (mq_waiter < 0) {
        return 678;
    }
    if (mq_waiter == 0) {
        close(mq_wait_started[0]);
        close(mq_wait_done[0]);
        char started = 'R';
        if (write(mq_wait_started[1], &started, 1) != 1) {
            _exit(1);
        }
        char received[16] = {0};
        ssize_t count = syscall(SYS_mq_timedreceive, mq_fd,
                                received, sizeof(received), NULL, NULL);
        char done = count == 5 && memcmp(received, "child", 5) == 0;
        if (write(mq_wait_done[1], &done, 1) != 1) {
            _exit(2);
        }
        _exit(done == 1 ? 0 : 3);
    }
    close(mq_wait_started[1]);
    close(mq_wait_done[1]);
    char wait_started = 0;
    struct timespec mq_waiter_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (read(mq_wait_started[0], &wait_started, 1) != 1 ||
        wait_started != 'R' ||
        nanosleep(&mq_waiter_delay, NULL) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "child", 5, 0, NULL) != 0) {
        return 679;
    }
    char wait_done = 0;
    int mq_waiter_status = 0;
    if (read(mq_wait_done[0], &wait_done, 1) != 1 ||
        wait_done != 1 ||
        waitpid(mq_waiter, &mq_waiter_status, 0) != mq_waiter ||
        !WIFEXITED(mq_waiter_status) ||
        WEXITSTATUS(mq_waiter_status) != 0 ||
        mq_notification_signals != 0 ||
        close(mq_wait_started[0]) != 0 ||
        close(mq_wait_done[0]) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "later", 5, 0, NULL) != 0) {
        return 680;
    }
    for (int attempt = 0; attempt < 8 && mq_notification_signals == 0;
         attempt++) {
        syscall(SYS_getpid);
    }
    memset(mq_first, 0, sizeof(mq_first));
    if (mq_notification_signals != 1 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 5 ||
        memcmp(mq_first, "later", 5) != 0) {
        return 681;
    }
    pid_t mq_notify_exit_child = fork();
    if (mq_notify_exit_child < 0) {
        return 688;
    }
    if (mq_notify_exit_child == 0) {
        _exit(syscall(SYS_mq_notify, mq_fd, &mq_none_event) == 0 ? 0 : 1);
    }
    int mq_notify_exit_status = 0;
    if (waitpid(mq_notify_exit_child, &mq_notify_exit_status, 0) !=
            mq_notify_exit_child ||
        !WIFEXITED(mq_notify_exit_status) ||
        WEXITSTATUS(mq_notify_exit_status) != 0 ||
        syscall(SYS_mq_notify, mq_fd, &mq_none_event) != 0 ||
        syscall(SYS_mq_notify, mq_fd, NULL) != 0) {
        return 689;
    }
    if (syscall(SYS_mq_notify, mq_fd, &mq_signal_event) != 0 ||
        syscall(SYS_mq_notify, mq_fd, NULL) != 0 ||
        sigprocmask(SIG_SETMASK, &mq_previous_mask, NULL) != 0 ||
        sigaction(SIGUSR1, &mq_previous_action, NULL) != 0) {
        return 665;
    }
    pid_t mq_permission_child = fork();
    if (mq_permission_child < 0) {
        return 667;
    }
    if (mq_permission_child == 0) {
        if (syscall(SYS_setresgid, 110, 110, 110) != 0 ||
            syscall(SYS_setresuid, 100, 100, 100) != 0) {
            _exit(1);
        }
        errno = 0;
        int denied = syscall(SYS_mq_open, mq_name, O_RDWR, 0, NULL);
        int open_denied = denied == -1 && errno == EACCES;
        errno = 0;
        int unlink_denied = syscall(SYS_mq_unlink, mq_name) == -1 &&
                            errno == EACCES;
        _exit(open_denied && unlink_denied ? 0 : 2);
    }
    int mq_permission_status = 0;
    if (waitpid(mq_permission_child, &mq_permission_status, 0) !=
            mq_permission_child ||
        !WIFEXITED(mq_permission_status) ||
        WEXITSTATUS(mq_permission_status) != 0) {
        return 668;
    }
    int mq_write_fd = syscall(SYS_mq_open, mq_name,
                              O_WRONLY | O_NONBLOCK, 0, NULL);
    struct mq_attr mq_write_attr = {0};
    if (mq_write_fd < 0 ||
        syscall(SYS_mq_getsetattr, mq_write_fd, NULL,
                &mq_write_attr) != 0 ||
        mq_write_attr.mq_maxmsg != 4 ||
        syscall(SYS_mq_notify, mq_write_fd, &mq_none_event) != 0 ||
        syscall(SYS_mq_notify, mq_write_fd, NULL) != 0 ||
        close(mq_write_fd) != 0) {
        return 669;
    }
    const char *mq_group_name = "jasper-mq-group-test";
    syscall(SYS_mq_unlink, mq_group_name);
    if (syscall(SYS_setfsgid, 120) != 0) {
        return 670;
    }
    int mq_group_fd = syscall(SYS_mq_open, mq_group_name,
                              O_CREAT | O_RDWR | O_NONBLOCK,
                              0660, &mq_attributes);
    if (syscall(SYS_setfsgid, 0) != 120 || mq_group_fd < 0) {
        return 671;
    }
    pid_t mq_group_child = fork();
    if (mq_group_child < 0) {
        return 672;
    }
    if (mq_group_child == 0) {
        gid_t supplementary_group = 120;
        if (syscall(SYS_setgroups, 1, &supplementary_group) != 0 ||
            syscall(SYS_setresgid, 110, 110, 110) != 0 ||
            syscall(SYS_setresuid, 100, 100, 100) != 0) {
            _exit(1);
        }
        int opened = syscall(SYS_mq_open, mq_group_name,
                             O_RDWR | O_NONBLOCK, 0, NULL);
        _exit(opened >= 0 ? 0 : 2);
    }
    int mq_group_status = 0;
    if (waitpid(mq_group_child, &mq_group_status, 0) != mq_group_child ||
        !WIFEXITED(mq_group_status) ||
        WEXITSTATUS(mq_group_status) != 0) {
        return 673;
    }
    pid_t mq_other_child = fork();
    if (mq_other_child < 0) {
        return 674;
    }
    if (mq_other_child == 0) {
        if (syscall(SYS_setgroups, 0, NULL) != 0 ||
            syscall(SYS_setresgid, 111, 111, 111) != 0 ||
            syscall(SYS_setresuid, 100, 100, 100) != 0) {
            _exit(1);
        }
        errno = 0;
        int denied = syscall(SYS_mq_open, mq_group_name,
                             O_RDWR | O_NONBLOCK, 0, NULL);
        _exit(denied == -1 && errno == EACCES ? 0 : 2);
    }
    int mq_other_status = 0;
    if (waitpid(mq_other_child, &mq_other_status, 0) != mq_other_child ||
        !WIFEXITED(mq_other_status) ||
        WEXITSTATUS(mq_other_status) != 0 ||
        close(mq_group_fd) != 0 ||
        syscall(SYS_mq_unlink, mq_group_name) != 0) {
        return 675;
    }
    errno = 0;
    if (syscall(SYS_mq_notify, mq_fd, NULL) != -1 || errno != EINVAL ||
        syscall(SYS_mq_unlink, mq_name) != 0 ||
        syscall(SYS_mq_timedsend, mq_fd, "live", 4, 0, NULL) != 0 ||
        syscall(SYS_mq_timedreceive, mq_fd, mq_first,
                sizeof(mq_first), NULL, NULL) != 4 ||
        memcmp(mq_first, "live", 4) != 0 ||
        close(mq_fd) != 0) {
        return 553;
    }
    errno = 0;
    if (syscall(SYS_mq_unlink, mq_name) != -1 || errno != ENOENT) {
        return 554;
    }
    errno = 0;
    if (syscall(SYS_epoll_ctl_old, -1, 0, -1, NULL) != -1 ||
        errno != ENOSYS) {
        return 556;
    }
    errno = 0;
    if (syscall(SYS_epoll_wait_old, -1, NULL, 0, 0) != -1 ||
        errno != ENOSYS) {
        return 557;
    }
    key_t sysv_msg_key = 0x4a534d51;
    int stale_sysv_msg = msgget(sysv_msg_key, 0);
    if (stale_sysv_msg >= 0) {
        msgctl(stale_sysv_msg, IPC_RMID, NULL);
    }
    int sysv_msg = msgget(sysv_msg_key, IPC_CREAT | IPC_EXCL | 0600);
    struct {
        long mtype;
        char mtext[64];
    } sysv_message = {0};
    if (sysv_msg < 0 ||
        msgget(sysv_msg_key, 0600) != sysv_msg) {
        return 564;
    }
    errno = 0;
    if (msgget(sysv_msg_key, IPC_CREAT | IPC_EXCL | 0600) != -1 ||
        errno != EEXIST) {
        return 565;
    }
    sysv_message.mtype = 3;
    strcpy(sysv_message.mtext, "three");
    if (msgsnd(sysv_msg, &sysv_message, 5, 0) != 0) {
        return 566;
    }
    sysv_message.mtype = 1;
    strcpy(sysv_message.mtext, "one");
    if (msgsnd(sysv_msg, &sysv_message, 3, 0) != 0) {
        return 567;
    }
    sysv_message.mtype = 2;
    strcpy(sysv_message.mtext, "two");
    if (msgsnd(sysv_msg, &sysv_message, 3, 0) != 0) {
        return 568;
    }
    struct msqid_ds sysv_message_status = {0};
    if (msgctl(sysv_msg, IPC_STAT, &sysv_message_status) != 0 ||
        sysv_message_status.msg_qnum != 3 ||
        sysv_message_status.msg_cbytes != 11 ||
        sysv_message_status.msg_perm.__key != sysv_msg_key) {
        return 569;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               0, IPC_NOWAIT) != 5 ||
        sysv_message.mtype != 3 ||
        memcmp(sysv_message.mtext, "three", 5) != 0) {
        return 570;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               -2, IPC_NOWAIT) != 3 ||
        sysv_message.mtype != 1 ||
        memcmp(sysv_message.mtext, "one", 3) != 0) {
        return 571;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               2, IPC_NOWAIT) != 3 ||
        sysv_message.mtype != 2 ||
        memcmp(sysv_message.mtext, "two", 3) != 0) {
        return 572;
    }
    errno = 0;
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               0, IPC_NOWAIT) != -1 || errno != ENOMSG) {
        return 573;
    }
    sysv_message.mtype = 4;
    strcpy(sysv_message.mtext, "copy");
    if (msgsnd(sysv_msg, &sysv_message, 4, 0) != 0) {
        return 574;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               0, IPC_NOWAIT | MSG_COPY) != 4 ||
        sysv_message.mtype != 4 ||
        memcmp(sysv_message.mtext, "copy", 4) != 0) {
        return 575;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               0, IPC_NOWAIT) != 4 ||
        memcmp(sysv_message.mtext, "copy", 4) != 0) {
        return 576;
    }
    sysv_message.mtype = 5;
    strcpy(sysv_message.mtext, "abcdef");
    if (msgsnd(sysv_msg, &sysv_message, 6, 0) != 0) {
        return 577;
    }
    errno = 0;
    if (msgrcv(sysv_msg, &sysv_message, 3, 0, IPC_NOWAIT) != -1 ||
        errno != E2BIG) {
        return 578;
    }
    memset(&sysv_message, 0, sizeof(sysv_message));
    if (msgrcv(sysv_msg, &sysv_message, 3, 0,
               IPC_NOWAIT | MSG_NOERROR) != 3 ||
        sysv_message.mtype != 5 ||
        memcmp(sysv_message.mtext, "abc", 3) != 0) {
        return 579;
    }
    pid_t sysv_receiver = fork();
    if (sysv_receiver < 0) {
        return 580;
    }
    if (sysv_receiver == 0) {
        memset(&sysv_message, 0, sizeof(sysv_message));
        ssize_t received = msgrcv(sysv_msg, &sysv_message,
                                  sizeof(sysv_message.mtext), 6, 0);
        _exit(received == 4 && sysv_message.mtype == 6 &&
                      memcmp(sysv_message.mtext, "wake", 4) == 0
                  ? 0
                  : 1);
    }
    sysv_message.mtype = 6;
    strcpy(sysv_message.mtext, "wake");
    int sysv_receiver_status = 0;
    struct timespec sysv_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (nanosleep(&sysv_delay, NULL) != 0 ||
        msgsnd(sysv_msg, &sysv_message, 4, 0) != 0 ||
        waitpid(sysv_receiver, &sysv_receiver_status, 0) != sysv_receiver ||
        !WIFEXITED(sysv_receiver_status) ||
        WEXITSTATUS(sysv_receiver_status) != 0 ||
        msgctl(sysv_msg, IPC_RMID, NULL) != 0) {
        return 581;
    }
    if (msgrcv(sysv_msg, &sysv_message, sizeof(sysv_message.mtext),
               0, IPC_NOWAIT) != -1) {
        return 582;
    }
    key_t sysv_sem_key = 0x53544d31;
    int stale_sysv_sem = semget(sysv_sem_key, 0, 0);
    if (stale_sysv_sem >= 0) {
        syscall(SYS_semctl, stale_sysv_sem, IPC_RMID, 0, 0);
    }
    int sysv_sem = semget(sysv_sem_key, 2, IPC_CREAT | IPC_EXCL | 0600);
    if (sysv_sem < 0 || semget(sysv_sem_key, 0, 0600) != sysv_sem ||
        syscall(SYS_semctl, sysv_sem, SETVAL, 0, 1) != 0 ||
        syscall(SYS_semctl, sysv_sem, GETVAL, 0, 0) != 1) {
        return 583;
    }
    struct sembuf semaphore_increment = {
        .sem_num = 0,
        .sem_op = 2,
        .sem_flg = 0,
    };
    if (semop(sysv_sem, &semaphore_increment, 1) != 0 ||
        syscall(SYS_semctl, sysv_sem, GETVAL, 0, 0) != 3) {
        return 584;
    }
    struct sembuf wait_zero = {
        .sem_num = 1,
        .sem_op = 0,
        .sem_flg = IPC_NOWAIT,
    };
    if (semop(sysv_sem, &wait_zero, 1) != 0 ||
        syscall(SYS_semctl, sysv_sem, SETVAL, 0, 0) != 0) {
        return 585;
    }
    pid_t semaphore_waiter = fork();
    if (semaphore_waiter < 0) {
        return 586;
    }
    if (semaphore_waiter == 0) {
        struct sembuf wait_positive = {
            .sem_num = 0,
            .sem_op = -1,
            .sem_flg = 0,
        };
        _exit(semop(sysv_sem, &wait_positive, 1) == 0 ? 0 : 1);
    }
    struct timespec semaphore_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (nanosleep(&semaphore_delay, NULL) != 0 ||
        syscall(SYS_semctl, sysv_sem, GETNCNT, 0, 0) != 1) {
        return 587;
    }
    struct sembuf wake_positive = {
        .sem_num = 0,
        .sem_op = 1,
        .sem_flg = 0,
    };
    int semaphore_status = 0;
    if (semop(sysv_sem, &wake_positive, 1) != 0 ||
        waitpid(semaphore_waiter, &semaphore_status, 0) != semaphore_waiter ||
        !WIFEXITED(semaphore_status) ||
        WEXITSTATUS(semaphore_status) != 0 ||
        syscall(SYS_semctl, sysv_sem, GETVAL, 0, 0) != 0) {
        return 588;
    }
    struct sembuf wait_missing = {
        .sem_num = 1,
        .sem_op = -1,
        .sem_flg = 0,
    };
    struct timespec semaphore_timeout = {.tv_sec = 0, .tv_nsec = 10000000};
    errno = 0;
    if (syscall(SYS_semtimedop, sysv_sem, &wait_missing, 1,
                &semaphore_timeout) != -1 || errno != EAGAIN) {
        return 589;
    }
    if (syscall(SYS_semctl, sysv_sem, SETVAL, 1, 1) != 0) {
        return 590;
    }
    pid_t undo_child = fork();
    if (undo_child < 0) {
        return 591;
    }
    if (undo_child == 0) {
        struct sembuf undo_wait = {
            .sem_num = 1,
            .sem_op = -1,
            .sem_flg = SEM_UNDO,
        };
        _exit(semop(sysv_sem, &undo_wait, 1) == 0 ? 0 : 1);
    }
    if (waitpid(undo_child, &semaphore_status, 0) != undo_child ||
        !WIFEXITED(semaphore_status) ||
        WEXITSTATUS(semaphore_status) != 0 ||
        syscall(SYS_semctl, sysv_sem, GETVAL, 1, 0) != 1) {
        return 592;
    }
    struct semid_ds sysv_sem_status = {0};
    if (syscall(SYS_semctl, sysv_sem, IPC_STAT, 0,
                &sysv_sem_status) != 0 ||
        sysv_sem_status.sem_nsems != 2 ||
        sysv_sem_status.sem_perm.__key != sysv_sem_key ||
        syscall(SYS_semctl, sysv_sem, IPC_RMID, 0, 0) != 0) {
        return 593;
    }
    key_t sysv_shm_key = 0x53484d31;
    int stale_sysv_shm = shmget(sysv_shm_key, 0, 0);
    if (stale_sysv_shm >= 0) {
        shmctl(stale_sysv_shm, IPC_RMID, NULL);
    }
    int sysv_shm = shmget(sysv_shm_key, 4096,
                          IPC_CREAT | IPC_EXCL | 0600);
    if (sysv_shm < 0 ||
        shmget(sysv_shm_key, 0, 0600) != sysv_shm) {
        return 594;
    }
    char *sysv_shared = shmat(sysv_shm, NULL, 0);
    if (sysv_shared == (char *)-1) {
        return 595;
    }
    strcpy(sysv_shared, "shared-memory");
    pid_t shm_inherited_child = fork();
    if (shm_inherited_child < 0) {
        return 682;
    }
    if (shm_inherited_child == 0) {
        struct shmid_ds inherited_status = {0};
        int ok = strcmp(sysv_shared, "shared-memory") == 0 &&
                 shmctl(sysv_shm, IPC_STAT, &inherited_status) == 0 &&
                 inherited_status.shm_nattch == 2;
        if (ok) {
            strcpy(sysv_shared, "child-update");
            ok = shmdt(sysv_shared) == 0;
        }
        _exit(ok ? 0 : 1);
    }
    int shm_inherited_status = 0;
    if (waitpid(shm_inherited_child, &shm_inherited_status, 0) !=
            shm_inherited_child ||
        !WIFEXITED(shm_inherited_status) ||
        WEXITSTATUS(shm_inherited_status) != 0 ||
        strcmp(sysv_shared, "child-update") != 0) {
        return 683;
    }
    struct shmid_ds shm_after_inherit = {0};
    if (shmctl(sysv_shm, IPC_STAT, &shm_after_inherit) != 0 ||
        shm_after_inherit.shm_nattch != 1) {
        return 684;
    }
    pid_t shm_vfork_child = vfork();
    if (shm_vfork_child < 0) {
        return 685;
    }
    if (shm_vfork_child == 0) {
        _exit(strcmp(sysv_shared, "child-update") == 0 ? 0 : 1);
    }
    if (waitpid(shm_vfork_child, &shm_inherited_status, 0) !=
            shm_vfork_child ||
        !WIFEXITED(shm_inherited_status) ||
        WEXITSTATUS(shm_inherited_status) != 0 ||
        strcmp(sysv_shared, "child-update") != 0) {
        return 686;
    }
    if (shmdt(sysv_shared) != 0) {
        return 596;
    }
    sysv_shared = shmat(sysv_shm, NULL, SHM_RDONLY);
    if (sysv_shared == (char *)-1 ||
        strcmp(sysv_shared, "child-update") != 0 ||
        shmdt(sysv_shared) != 0) {
        return 597;
    }
    pid_t shm_reader = fork();
    if (shm_reader < 0) {
        return 598;
    }
    if (shm_reader == 0) {
        char *mapping = shmat(sysv_shm, NULL, SHM_RDONLY);
        int result = mapping != (char *)-1 &&
                     strcmp(mapping, "child-update") == 0 &&
                     shmdt(mapping) == 0;
        _exit(result ? 0 : 1);
    }
    int shm_status = 0;
    if (waitpid(shm_reader, &shm_status, 0) != shm_reader ||
        !WIFEXITED(shm_status) || WEXITSTATUS(shm_status) != 0) {
        return 599;
    }
    struct shmid_ds sysv_shm_status = {0};
    if (shmctl(sysv_shm, IPC_STAT, &sysv_shm_status) != 0 ||
        sysv_shm_status.shm_segsz != 4096 ||
        sysv_shm_status.shm_nattch != 0 ||
        sysv_shm_status.shm_perm.__key != sysv_shm_key) {
        return 600;
    }
    sysv_shared = shmat(sysv_shm, NULL, 0);
    if (sysv_shared == (char *)-1 ||
        shmctl(sysv_shm, IPC_RMID, NULL) != 0 ||
        strcmp(sysv_shared, "child-update") != 0 ||
        shmdt(sysv_shared) != 0) {
        return 601;
    }
    errno = 0;
    if (shmget(sysv_shm_key, 0, 0) != -1 || errno != ENOENT) {
        return 602;
    }
    struct mnt_id_req mount_request = {
        .size = sizeof(mount_request),
        .mnt_id = LSMT_ROOT,
        .param = 0,
    };
    uint64_t mount_ids[2] = {0};
    if (syscall(SYS_listmount, &mount_request, mount_ids, 2, 0) != 1 ||
        mount_ids[0] == 0) {
        return 603;
    }
    mount_request.param = mount_ids[0];
    if (syscall(SYS_listmount, &mount_request, mount_ids, 2, 0) != 0) {
        return 604;
    }
    struct ns_id_req namespace_request = {
        .size = sizeof(namespace_request),
        .ns_id = 0,
        .ns_type = 0,
        .user_ns_id = 0,
    };
    uint64_t namespace_ids[8] = {0};
    if (syscall(SYS_listns, &namespace_request, namespace_ids,
                8, 0) != 8 ||
        namespace_ids[0] != 1 || namespace_ids[7] != 8) {
        return 646;
    }
    namespace_request.ns_id = namespace_ids[7];
    if (syscall(SYS_listns, &namespace_request, namespace_ids,
                8, 0) != 0) {
        return 647;
    }
    namespace_request.ns_id = 0;
    namespace_request.ns_type = USER_NS;
    if (syscall(SYS_listns, &namespace_request, namespace_ids,
                8, 0) != 1 || namespace_ids[0] != 3) {
        return 648;
    }
    size_t statmount_size = sizeof(struct statmount) + 256;
    struct statmount *mount_status = calloc(1, statmount_size);
    mount_request.mnt_id = mount_ids[0];
    mount_request.param = 0xffffffffU;
    if (!mount_status ||
        syscall(SYS_statmount, &mount_request, mount_status,
                statmount_size, 0) != 0 ||
        mount_status->size < sizeof(struct statmount) ||
        mount_status->mnt_id != mount_ids[0] ||
        mount_status->mnt_parent_id != mount_ids[0] ||
        (mount_status->mask & (STATMOUNT_FS_TYPE |
                               STATMOUNT_MNT_ROOT |
                               STATMOUNT_MNT_POINT)) !=
            (STATMOUNT_FS_TYPE | STATMOUNT_MNT_ROOT |
             STATMOUNT_MNT_POINT) ||
        strcmp(mount_status->str + mount_status->fs_type, "jasperfs") != 0 ||
        strcmp(mount_status->str + mount_status->mnt_root, "/") != 0 ||
        strcmp(mount_status->str + mount_status->mnt_point, "/") != 0) {
        return 605;
    }
    free(mount_status);
    uint64_t lsm_ids[2] = {0};
    uint32_t lsm_size = sizeof(lsm_ids);
    if (syscall(SYS_lsm_list_modules, lsm_ids, &lsm_size, 0) != 1 ||
        lsm_size != sizeof(uint64_t) ||
        lsm_ids[0] != LSM_ID_CAPABILITY) {
        return 615;
    }
    lsm_size = 0;
    errno = 0;
    if (syscall(SYS_lsm_list_modules, lsm_ids, &lsm_size, 0) != -1 ||
        errno != E2BIG || lsm_size != sizeof(uint64_t)) {
        return 616;
    }
    unsigned char lsm_context_bytes[512] __attribute__((aligned(8))) = {0};
    uint32_t lsm_context_size = sizeof(lsm_context_bytes);
    if (syscall(SYS_lsm_get_self_attr, LSM_ATTR_CURRENT,
                lsm_context_bytes, &lsm_context_size, 0) != 1 ||
        lsm_context_size < sizeof(struct lsm_ctx) ||
        ((struct lsm_ctx *)lsm_context_bytes)->len != lsm_context_size ||
        ((struct lsm_ctx *)lsm_context_bytes)->ctx_len < 9 ||
        memcmp(((struct lsm_ctx *)lsm_context_bytes)->ctx,
               "jasper:v", 8) != 0) {
        return 634;
    }
    memset(main_thread_name, 0, sizeof(main_thread_name));
    prctl(PR_GET_NAME, main_thread_name, 0, 0, 0);
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
    int memory_policy = -1;
    unsigned long memory_nodes = ~0UL;
    if (syscall(SYS_get_mempolicy, &memory_policy, &memory_nodes,
                8 * sizeof(memory_nodes), NULL, 0) != 0 ||
        memory_policy != MPOL_DEFAULT || memory_nodes != 0 ||
        syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0) != 0) {
        return 638;
    }
    memory_nodes = 0;
    if (syscall(SYS_get_mempolicy, NULL, &memory_nodes,
                8 * sizeof(memory_nodes), NULL,
                MPOL_F_MEMS_ALLOWED) != 0 ||
        (memory_nodes & 1UL) == 0) {
        return 639;
    }
    errno = 0;
    if (syscall(SYS_set_mempolicy, MPOL_BIND, NULL, 0) != -1 ||
        errno != EINVAL) {
        return 640;
    }
    void *mempolicy_memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mempolicy_memory == MAP_FAILED ||
        syscall(SYS_mbind, mempolicy_memory, 4096, MPOL_DEFAULT,
                NULL, 0, MPOL_MF_STRICT) != 0 ||
        syscall(SYS_set_mempolicy_home_node, mempolicy_memory,
                4096, 0, 0) != 0) {
        return 641;
    }
    void *move_pages_addresses[2] = {
        mempolicy_memory,
        (void *)-4096,
    };
    int move_pages_nodes[2] = {0, 0};
    int move_pages_status[2] = {99, 99};
    unsigned long migrate_mask = 1UL;
    if (syscall(SYS_move_pages, 0, 2, move_pages_addresses,
                NULL, move_pages_status, 0) != 1 ||
        move_pages_status[0] != 0 ||
        move_pages_status[1] != -ENOENT ||
        syscall(SYS_move_pages, 0, 1, move_pages_addresses,
                move_pages_nodes, move_pages_status,
                MPOL_MF_MOVE) != 0 ||
        move_pages_status[0] != 0 ||
        syscall(SYS_migrate_pages, 0, 64,
                &migrate_mask, &migrate_mask) != 0 ||
        munmap(mempolicy_memory, 4096) != 0) {
        return 642;
    }
    enum {
        KEYCTL_GET_KEYRING_ID = 0,
        KEYCTL_UPDATE = 2,
        KEYCTL_REVOKE = 3,
        KEYCTL_CHOWN = 4,
        KEYCTL_SETPERM = 5,
        KEYCTL_DESCRIBE = 6,
        KEYCTL_CLEAR = 7,
        KEYCTL_LINK = 8,
        KEYCTL_UNLINK = 9,
        KEYCTL_SEARCH = 10,
        KEYCTL_READ = 11,
        KEYCTL_GET_SECURITY = 17,
        KEYCTL_CAPABILITIES = 31,
        KEY_SPEC_PROCESS_KEYRING = -2,
    };
    int keyring = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID,
                          KEY_SPEC_PROCESS_KEYRING, 1);
    int key_serial = syscall(SYS_add_key, "user", "jasper-key",
                             "key-value", 9, keyring);
    char key_buffer[32] = {0};
    if (keyring < 0 || key_serial < 0 ||
        syscall(SYS_request_key, "user", "jasper-key", NULL,
                keyring) != key_serial ||
        syscall(SYS_keyctl, KEYCTL_READ, key_serial, NULL, 0) != 9 ||
        syscall(SYS_keyctl, KEYCTL_READ, key_serial,
                key_buffer, sizeof(key_buffer)) != 9 ||
        memcmp(key_buffer, "key-value", 9) != 0 ||
        syscall(SYS_keyctl, KEYCTL_DESCRIBE, key_serial,
                key_buffer, sizeof(key_buffer)) != 10 ||
        memcmp(key_buffer, "jasper-key", 10) != 0 ||
        syscall(SYS_keyctl, KEYCTL_SEARCH, keyring,
                "user", "jasper-key") != key_serial ||
        syscall(SYS_keyctl, KEYCTL_CHOWN, key_serial, 0, 0) != 0 ||
        syscall(SYS_keyctl, KEYCTL_SETPERM, key_serial,
                0x3f3f3f00) != 0 ||
        syscall(SYS_keyctl, KEYCTL_GET_SECURITY, key_serial,
                key_buffer, sizeof(key_buffer)) <= 0 ||
        memcmp(key_buffer, "jasper-key:", 11) != 0 ||
        syscall(SYS_keyctl, KEYCTL_UPDATE, key_serial,
                "updated", 7) != 0 ||
        syscall(SYS_keyctl, KEYCTL_UNLINK, key_serial, keyring) != 0 ||
        syscall(SYS_keyctl, KEYCTL_LINK, key_serial, keyring) != 0 ||
        syscall(SYS_keyctl, KEYCTL_REVOKE, key_serial) != 0) {
        return 645;
    }
    errno = 0;
    if (syscall(SYS_keyctl, KEYCTL_SEARCH, keyring,
                "user", "missing-key") != -1 || errno != ENOKEY) {
        return 649;
    }
    int cleared_key = syscall(SYS_add_key, "user", "clear-key",
                              "clear", 5, keyring);
    if (cleared_key < 0 ||
        syscall(SYS_keyctl, KEYCTL_CLEAR, keyring) != 0) {
        return 650;
    }
    errno = 0;
    if (syscall(SYS_keyctl, KEYCTL_SEARCH, keyring,
                "user", "clear-key") != -1 || errno != ENOKEY) {
        return 651;
    }
    unsigned char key_capabilities[2] = {0};
    if (syscall(SYS_keyctl, KEYCTL_CAPABILITIES,
                key_capabilities, sizeof(key_capabilities)) != 0 ||
        (key_capabilities[0] & 0x21) != 0x21) {
        return 653;
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
    struct rusage process_usage = {0};
    struct rusage thread_usage = {0};
    struct rusage child_usage = {0};
    errno = 0;
    int self_usage_result = getrusage(RUSAGE_SELF, &process_usage);
    int self_usage_errno = errno;
    errno = 0;
    int thread_usage_result = getrusage(RUSAGE_THREAD, &thread_usage);
    int thread_usage_errno = errno;
    if (self_usage_result != 0 ||
        (process_usage.ru_utime.tv_sec == 0 &&
         process_usage.ru_utime.tv_usec == 0) ||
        thread_usage_result != 0 ||
        (thread_usage.ru_utime.tv_sec == 0 &&
         thread_usage.ru_utime.tv_usec == 0)) {
        printf("getrusage-fail self=%d errno=%d utime=%ld.%06ld "
               "thread=%d errno=%d utime=%ld.%06ld\n",
               self_usage_result, self_usage_errno,
               (long)process_usage.ru_utime.tv_sec,
               (long)process_usage.ru_utime.tv_usec,
               thread_usage_result, thread_usage_errno,
               (long)thread_usage.ru_utime.tv_sec,
               (long)thread_usage.ru_utime.tv_usec);
        return 360;
    }
    if (getrusage(RUSAGE_CHILDREN, &child_usage) != 0 ||
        (child_usage.ru_utime.tv_sec == 0 &&
         child_usage.ru_utime.tv_usec == 0)) {
        return 361;
    }
    struct tms process_times = {0};
    if (times(&process_times) <= 0 || process_times.tms_utime == 0 ||
        process_times.tms_cutime == 0) {
        return 363;
    }
    if (times(NULL) <= 0) {
        return 364;
    }
    errno = 0;
    if (syscall(SYS_getrusage, RUSAGE_SELF, (void *)1) != -1 ||
        errno != EFAULT) {
        return 362;
    }
    errno = 0;
    if (syscall(SYS_times, (void *)1) != -1 || errno != EFAULT) {
        return 365;
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
    int pdeath_ready[2];
    int pdeath_done[2];
    if (pipe(pdeath_ready) != 0 || pipe(pdeath_done) != 0) {
        return 698;
    }
    pid_t pdeath_parent = fork();
    if (pdeath_parent < 0) {
        return 698;
    }
    if (pdeath_parent == 0) {
        pid_t pdeath_child = fork();
        if (pdeath_child < 0) {
            _exit(1);
        }
        if (pdeath_child == 0) {
            close(pdeath_ready[0]);
            close(pdeath_done[0]);
            pdeath_done_fd = pdeath_done[1];
            if (signal(SIGTERM, pdeath_signal_handler) == SIG_ERR ||
                prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0) != 0) {
                _exit(2);
            }
            int configured = 0;
            if (prctl(PR_GET_PDEATHSIG, &configured, 0, 0, 0) != 0 ||
                configured != SIGTERM) {
                _exit(3);
            }
            char ready = 'R';
            if (write(pdeath_ready[1], &ready, 1) != 1) {
                _exit(4);
            }
            for (;;) {
                pause();
            }
        }
        close(pdeath_ready[1]);
        close(pdeath_done[0]);
        close(pdeath_done[1]);
        char ready = 0;
        _exit(read(pdeath_ready[0], &ready, 1) == 1 &&
                      ready == 'R'
                  ? 0
                  : 5);
    }
    close(pdeath_ready[0]);
    close(pdeath_ready[1]);
    close(pdeath_done[1]);
    child_status = 0;
    char pdeath_byte = 0;
    struct pollfd pdeath_poll = {
        .fd = pdeath_done[0],
        .events = POLLIN,
    };
    if (waitpid(pdeath_parent, &child_status, 0) != pdeath_parent ||
        !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0 ||
        poll(&pdeath_poll, 1, 1000) != 1 ||
        (pdeath_poll.revents & POLLIN) == 0 ||
        read(pdeath_done[0], &pdeath_byte, 1) != 1 ||
        pdeath_byte != 'D' ||
        close(pdeath_done[0]) != 0) {
        return 699;
    }
    int subreaper_enabled = 0;
    if (prctl(PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) != 0 ||
        prctl(PR_GET_CHILD_SUBREAPER, &subreaper_enabled, 0, 0, 0) != 0 ||
        subreaper_enabled != 0 ||
        prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0 ||
        prctl(PR_GET_CHILD_SUBREAPER, &subreaper_enabled, 0, 0, 0) != 0 ||
        subreaper_enabled != 1) {
        return 700;
    }
    int subreaper_pipe[2];
    if (pipe(subreaper_pipe) != 0) {
        return 701;
    }
    pid_t subreaper_parent = fork();
    if (subreaper_parent < 0) {
        return 701;
    }
    if (subreaper_parent == 0) {
        close(subreaper_pipe[0]);
        pid_t subreaper_child = fork();
        if (subreaper_child < 0) {
            _exit(1);
        }
        if (subreaper_child == 0) {
            close(subreaper_pipe[1]);
            struct timespec orphan_delay = {
                .tv_sec = 0,
                .tv_nsec = 1000000,
            };
            for (int attempt = 0; attempt < 1000; attempt++) {
                if (getppid() == fork_parent_pid) {
                    break;
                }
                nanosleep(&orphan_delay, NULL);
            }
            _exit(getppid() == fork_parent_pid ? 0 : 2);
        }
        if (write(subreaper_pipe[1], &subreaper_child,
                  sizeof(subreaper_child)) !=
            (ssize_t)sizeof(subreaper_child)) {
            _exit(3);
        }
        _exit(0);
    }
    close(subreaper_pipe[1]);
    pid_t adopted_child = -1;
    if (read(subreaper_pipe[0], &adopted_child,
             sizeof(adopted_child)) !=
            (ssize_t)sizeof(adopted_child) ||
        adopted_child <= 0 ||
        close(subreaper_pipe[0]) != 0) {
        return 702;
    }
    child_status = 0;
    if (waitpid(subreaper_parent, &child_status, 0) !=
            subreaper_parent ||
        !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        return 703;
    }
    child_status = 0;
    if (waitpid(adopted_child, &child_status, 0) != adopted_child ||
        !WIFEXITED(child_status) ||
        WEXITSTATUS(child_status) != 0) {
        return 704;
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
    errno = 0;
    if (getpgrp() != process_id || getpgid(0) != process_id ||
        getsid(0) != process_id || setpgid(0, 0) != -1 ||
        errno != EPERM ||
        getresuid(&real_uid, &effective_uid, &saved_uid) != 0 ||
        real_uid != 0 || effective_uid != 0 || saved_uid != 0 ||
        getresgid(&real_gid, &effective_gid, &saved_gid) != 0 ||
        real_gid != 0 || effective_gid != 0 || saved_gid != 0) {
        return 217;
    }
    errno = 0;
    if (setsid() != -1 || errno != EPERM) {
        return 341;
    }
    pid_t group_child = fork();
    if (group_child < 0) {
        return 342;
    }
    if (group_child == 0) {
        pid_t child_id = getpid();
        pid_t parent_group = getppid();
        if (child_id == parent_group || getpgrp() != parent_group ||
            getpgid(0) != parent_group ||
            getsid(0) != parent_group || setpgid(0, 0) != 0 ||
            getpgrp() != child_id || getpgid(0) != child_id ||
            getsid(0) != parent_group) {
            _exit(343);
        }
        errno = 0;
        _exit(setsid() == -1 && errno == EPERM ? 0 : 344);
    }
    child_status = 0;
    if (waitpid(group_child, &child_status, 0) != group_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        return 345;
    }
    pid_t session_child = fork();
    if (session_child < 0) {
        return 346;
    }
    if (session_child == 0) {
        pid_t child_id = getpid();
        if (getpgrp() == child_id || setsid() != child_id ||
            getpgrp() != child_id || getpgid(0) != child_id ||
            getsid(0) != child_id) {
            _exit(347);
        }
        _exit(0);
    }
    child_status = 0;
    if (waitpid(session_child, &child_status, 0) != session_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        return 348;
    }
    int process_madvise_pidfd = syscall(SYS_pidfd_open, getpid(), 0);
    void *process_madvise_memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec process_madvise_vector = {
        .iov_base = process_madvise_memory,
        .iov_len = 4096,
    };
    if (process_madvise_pidfd < 0 ||
        process_madvise_memory == MAP_FAILED ||
        syscall(SYS_process_madvise, process_madvise_pidfd,
                &process_madvise_vector, 1, MADV_WILLNEED, 0) != 4096) {
        return 618;
    }
    errno = 0;
    if (syscall(SYS_process_madvise, process_madvise_pidfd,
                &process_madvise_vector, 1, MADV_WILLNEED, 1) != -1 ||
        errno != EINVAL ||
        close(process_madvise_pidfd) != 0 ||
        munmap(process_madvise_memory, 4096) != 0) {
        return 619;
    }
    int mrelease_pipe[2];
    if (pipe2(mrelease_pipe, O_CLOEXEC) != 0) {
        return 623;
    }
    pid_t mrelease_child = fork();
    if (mrelease_child < 0) {
        return 624;
    }
    if (mrelease_child == 0) {
        close(mrelease_pipe[1]);
        char byte = 0;
        ssize_t released = read(mrelease_pipe[0], &byte, 1);
        _exit(released == 1 && byte == 'R' ? 0 : 1);
    }
    close(mrelease_pipe[0]);
    int mrelease_pidfd = syscall(SYS_pidfd_open, mrelease_child, 0);
    if (mrelease_pidfd < 0 ||
        write(mrelease_pipe[1], "R", 1) != 1 ||
        close(mrelease_pipe[1]) != 0) {
        return 625;
    }
    struct timespec mrelease_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    nanosleep(&mrelease_delay, NULL);
    if (syscall(SYS_process_mrelease, mrelease_pidfd, 0) != 0 ||
        close(mrelease_pidfd) != 0 ||
        waitpid(mrelease_child, &child_status, 0) != mrelease_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        return 626;
    }
    errno = 0;
    if (syscall(SYS_pkey_alloc, 0, 0) != -1 || errno != ENOSPC ||
        syscall(SYS_pkey_alloc, 1, 0) != -1 || errno != EINVAL ||
        syscall(SYS_pkey_free, 0) != -1 || errno != EINVAL) {
        return 627;
    }
    void *pkey_memory = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pkey_memory == MAP_FAILED ||
        syscall(SYS_pkey_mprotect, pkey_memory, 4096,
                PROT_READ, 0) != 0) {
        return 628;
    }
    errno = 0;
    if (syscall(SYS_pkey_mprotect, pkey_memory, 4096,
                PROT_READ, 1) != -1 || errno != EINVAL ||
        munmap(pkey_memory, 4096) != 0) {
        return 629;
    }
    uint32_t seccomp_errno = SECCOMP_RET_ERRNO | EPERM;
    uint32_t invalid_seccomp_action = 0x12340000U;
    struct seccomp_notif_sizes seccomp_sizes = {0};
    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                &seccomp_errno) != 0 ||
        syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0,
                &seccomp_sizes) != 0 ||
        seccomp_sizes.seccomp_notif == 0 ||
        seccomp_sizes.seccomp_notif_resp == 0 ||
        seccomp_sizes.seccomp_data != 64) {
        return 610;
    }
    errno = 0;
    if (syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0,
                &invalid_seccomp_action) != -1 ||
        errno != EINVAL) {
        return 611;
    }
    struct sock_filter seccomp_code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getcwd, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog seccomp_program = {
        .len = sizeof(seccomp_code) / sizeof(seccomp_code[0]),
        .filter = seccomp_code,
    };
    pid_t seccomp_prctl_child = fork();
    if (seccomp_prctl_child < 0) {
        return 696;
    }
    if (seccomp_prctl_child == 0) {
        errno = 0;
        if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 0 ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                  &seccomp_program, 0, 0) != -1 ||
            errno != EACCES ||
            prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                  &seccomp_program, 0, 0) != 0 ||
            prctl(PR_GET_SECCOMP, 0, 0, 0, 0) !=
                SECCOMP_MODE_FILTER) {
            _exit(1);
        }
        char child_cwd[64];
        errno = 0;
        int denied = syscall(SYS_getcwd, child_cwd,
                             sizeof(child_cwd));
        _exit(denied == -1 && errno == EPERM ? 0 : 2);
    }
    int seccomp_prctl_status = 0;
    if (waitpid(seccomp_prctl_child, &seccomp_prctl_status, 0) !=
            seccomp_prctl_child ||
        !WIFEXITED(seccomp_prctl_status) ||
        WEXITSTATUS(seccomp_prctl_status) != 0) {
        return 697;
    }
    errno = 0;
    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
                &seccomp_program) != -1 || errno != EACCES ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 0 ||
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0,
                &seccomp_program) != 0) {
        return 612;
    }
    char seccomp_cwd[64];
    errno = 0;
    if (syscall(SYS_getcwd, seccomp_cwd, sizeof(seccomp_cwd)) != -1 ||
        errno != EPERM) {
        return 613;
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
    syscall(SYS_execveat, AT_FDCWD, exec_argv[0],
            exec_argv, exec_envp, 0);
    printf("jasper-exec-fail errno=%d\n", errno);
    return 61;
}
