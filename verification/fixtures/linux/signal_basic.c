// Exercise glibc sigaction, raise/tgkill, blocking and nested rt_sigreturn.
// 使用未修改的 Ubuntu glibc 验证 sigaction、raise/tgkill、屏蔽与嵌套 rt_sigreturn。
#define _GNU_SOURCE

#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <ucontext.h>
#include <unistd.h>

static volatile sig_atomic_t usr1_count;
static volatile sig_atomic_t usr2_count;
static volatile sig_atomic_t nested_ok;
static volatile sig_atomic_t blocked_worker_tid;
static volatile sig_atomic_t open_worker_tid;
static volatile sig_atomic_t blocked_mask_ready;
static volatile sig_atomic_t release_blocked_worker;
static volatile sig_atomic_t blocked_worker_signal;
static volatile sig_atomic_t open_worker_signal;
static volatile sig_atomic_t futex_worker_tid;
static volatile sig_atomic_t futex_worker_ready;
static volatile sig_atomic_t futex_worker_signal;
static int futex_word;

static void usr2_handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal != SIGUSR2 || info == 0 || info->si_signo != signal ||
        info->si_pid != getpid() || context == 0) {
        _exit(11);
    }
    usr2_count++;
}

static void usr1_handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal != SIGUSR1 || info == 0 || info->si_signo != signal ||
        info->si_pid != getpid() || context == 0) {
        _exit(12);
    }
    if (syscall(SYS_gettid) == blocked_worker_tid) {
        blocked_worker_signal = 1;
        return;
    }
    if (syscall(SYS_gettid) == open_worker_tid) {
        open_worker_signal = 1;
        return;
    }
    if (syscall(SYS_gettid) == futex_worker_tid) {
        futex_worker_signal = 1;
        return;
    }
    if (((ucontext_t *)context)->uc_mcontext.gregs[REG_RIP] == 0) {
        _exit(14);
    }
    usr1_count++;
    if (usr1_count == 1) {
        if (raise(SIGUSR2) != 0) {
            _exit(13);
        }
        nested_ok = usr2_count == 1;
    }
}

static void *blocked_worker(void *argument) {
    (void)argument;
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (pthread_sigmask(SIG_BLOCK, &blocked, 0) != 0) {
        return (void *)(intptr_t)-1;
    }
    blocked_worker_tid = syscall(SYS_gettid);
    blocked_mask_ready = 1;
    while (!release_blocked_worker) {
        syscall(SYS_sched_yield);
    }
    if (pthread_sigmask(SIG_UNBLOCK, &blocked, 0) != 0) {
        return (void *)(intptr_t)-2;
    }
    while (!blocked_worker_signal) {
        syscall(SYS_sched_yield);
    }
    return (void *)(intptr_t)blocked_worker_signal;
}

static void *open_worker(void *argument) {
    (void)argument;
    open_worker_tid = syscall(SYS_gettid);
    while (!open_worker_signal) {
        syscall(SYS_sched_yield);
    }
    return (void *)(intptr_t)open_worker_signal;
}

static void *futex_worker(void *argument) {
    (void)argument;
    futex_worker_tid = syscall(SYS_gettid);
    __atomic_store_n(&futex_word, 0, __ATOMIC_RELEASE);
    futex_worker_ready = 1;
    long result = syscall(SYS_futex, &futex_word, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    if (result == -1 && errno == EINTR && futex_worker_signal) {
        return (void *)(intptr_t)1;
    }
    return (void *)(intptr_t)-3;
}

static int install_handler(int signal, void (*handler)(int, siginfo_t *, void *)) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    return sigaction(signal, &action, 0);
}

int main(void) {
    if (install_handler(SIGUSR1, usr1_handler) != 0 ||
        install_handler(SIGUSR2, usr2_handler) != 0) {
        return 1;
    }
    if (raise(SIGUSR1) != 0 || usr1_count != 1 || usr2_count != 1 || !nested_ok) {
        return 2;
    }

    sigset_t blocked;
    sigset_t old;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &blocked, &old) != 0) {
        return 3;
    }
    if (raise(SIGUSR1) != 0 || usr1_count != 1) {
        return 4;
    }
    if (sigprocmask(SIG_SETMASK, &old, 0) != 0 || usr1_count != 2) {
        return 5;
    }

    pthread_t blocked_thread;
    pthread_t open_thread;
    void *blocked_result = 0;
    void *open_result = 0;
    if (pthread_create(&blocked_thread, 0, blocked_worker, 0) != 0 ||
        pthread_create(&open_thread, 0, open_worker, 0) != 0) {
        return 6;
    }
    while (blocked_worker_tid == 0 || open_worker_tid == 0 || !blocked_mask_ready) {
        syscall(SYS_sched_yield);
    }

    sigset_t main_mask;
    if (sigprocmask(SIG_SETMASK, 0, &main_mask) != 0 || sigismember(&main_mask, SIGUSR1)) {
        return 7;
    }
    if (pthread_kill(blocked_thread, SIGUSR1) != 0 ||
        pthread_kill(open_thread, SIGUSR1) != 0) {
        return 8;
    }
    for (int attempt = 0; attempt < 10000 && open_worker_signal == 0; attempt++) {
        syscall(SYS_sched_yield);
    }
    if (open_worker_signal != 1 || blocked_worker_signal != 0) {
        return 9;
    }
    release_blocked_worker = 1;
    if (pthread_join(blocked_thread, &blocked_result) != 0 ||
        pthread_join(open_thread, &open_result) != 0 ||
        blocked_result != (void *)(intptr_t)1 ||
        open_result != (void *)(intptr_t)1 || usr1_count != 2) {
        return 10;
    }
    blocked_worker_tid = 0;
    open_worker_tid = 0;

    pthread_t futex_thread;
    void *futex_result = 0;
    if (pthread_create(&futex_thread, 0, futex_worker, 0) != 0) {
        return 11;
    }
    while (!futex_worker_ready) {
        syscall(SYS_sched_yield);
    }
    if (pthread_kill(futex_thread, SIGUSR1) != 0 ||
        pthread_join(futex_thread, &futex_result) != 0 ||
        futex_result != (void *)(intptr_t)1) {
        return 12;
    }
    futex_worker_tid = 0;

    static const char message[] = "jasper-signal-ok\n";
    if (write(STDOUT_FILENO, message, sizeof(message) - 1) !=
        (ssize_t)(sizeof(message) - 1)) {
        return 13;
    }
    return 0;
}
