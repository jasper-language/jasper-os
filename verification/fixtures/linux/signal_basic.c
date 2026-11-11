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
static volatile sig_atomic_t restart_worker_tid;
static volatile sig_atomic_t restart_worker_ready;
static volatile sig_atomic_t restart_worker_signal;
static int restart_futex_word;
static volatile sig_atomic_t alarm_count;
static volatile sig_atomic_t term_count;

static void usr2_handler(int signal, siginfo_t *info, void *context) {
    (void)context;
    if (signal != SIGUSR2 || info == 0 || info->si_signo != signal ||
        info->si_pid != getpid() || context == 0) {
        _exit(11);
    }
    if (syscall(SYS_gettid) == restart_worker_tid) {
        restart_worker_signal = 1;
        return;
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

static void alarm_handler(int signal, siginfo_t *info, void *context) {
    if (signal != SIGALRM || info == 0 || info->si_signo != signal ||
        info->si_pid != getpid() || context == 0) {
        _exit(17);
    }
    alarm_count++;
    if (alarm_count == 1 && raise(SIGALRM) != 0) {
        _exit(18);
    }
}

static void term_handler(int signal, siginfo_t *info, void *context) {
    if (signal != SIGTERM || info == 0 || info->si_signo != signal ||
        info->si_pid != getpid() || context == 0) {
        _exit(19);
    }
    term_count++;
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

static void *restart_worker(void *argument) {
    (void)argument;
    restart_worker_tid = syscall(SYS_gettid);
    __atomic_store_n(&restart_futex_word, 0, __ATOMIC_RELEASE);
    restart_worker_ready = 1;
    long result =
        syscall(SYS_futex, &restart_futex_word, FUTEX_WAIT_PRIVATE, 0, 0, 0, 0);
    if (result == 0 && restart_worker_signal == 1) {
        return (void *)(intptr_t)1;
    }
    return (void *)(intptr_t)-4;
}

static int install_handler_flags(int signal, void (*handler)(int, siginfo_t *, void *),
                                 int flags) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_sigaction = handler;
    action.sa_flags = flags;
    sigemptyset(&action.sa_mask);
    return sigaction(signal, &action, 0);
}

int main(void) {
    if (install_handler_flags(SIGUSR1, usr1_handler, SA_SIGINFO) != 0 ||
        install_handler_flags(SIGUSR2, usr2_handler, SA_SIGINFO | SA_RESTART) != 0 ||
        install_handler_flags(SIGALRM, alarm_handler, SA_SIGINFO | SA_NODEFER) != 0 ||
        install_handler_flags(SIGTERM, term_handler, SA_SIGINFO | SA_RESETHAND) != 0) {
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

    if (raise(SIGALRM) != 0 || alarm_count != 2) {
        return 17;
    }
    struct sigaction alarm_action;
    if (sigaction(SIGALRM, 0, &alarm_action) != 0 ||
        alarm_action.sa_sigaction != alarm_handler) {
        return 18;
    }

    if (raise(SIGTERM) != 0 || term_count != 1) {
        return 19;
    }
    struct sigaction term_action;
    if (sigaction(SIGTERM, 0, &term_action) != 0 ||
        term_action.sa_handler != SIG_DFL) {
        return 20;
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

    pthread_t restart_thread;
    void *restart_result = 0;
    if (pthread_create(&restart_thread, 0, restart_worker, 0) != 0) {
        return 13;
    }
    while (!restart_worker_ready) {
        syscall(SYS_sched_yield);
    }
    if (pthread_kill(restart_thread, SIGUSR2) != 0) {
        return 14;
    }
    while (restart_worker_signal == 0) {
        syscall(SYS_sched_yield);
    }
    for (int attempt = 0; attempt < 1000; attempt++) {
        syscall(SYS_sched_yield);
    }
    __atomic_store_n(&restart_futex_word, 1, __ATOMIC_RELEASE);
    if (syscall(SYS_futex, &restart_futex_word, FUTEX_WAKE_PRIVATE, 1, 0, 0, 0) < 1 ||
        pthread_join(restart_thread, &restart_result) != 0 ||
        restart_result != (void *)(intptr_t)1) {
        return 15;
    }
    restart_worker_tid = 0;

    static const char message[] = "jasper-signal-ok\n";
    if (write(STDOUT_FILENO, message, sizeof(message) - 1) !=
        (ssize_t)(sizeof(message) - 1)) {
        return 16;
    }
    return 0;
}
