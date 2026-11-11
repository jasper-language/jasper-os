// Exercise glibc sigaction, raise/tgkill, blocking and nested rt_sigreturn.
// 使用未修改的 Ubuntu glibc 验证 sigaction、raise/tgkill、屏蔽与嵌套 rt_sigreturn。
#define _GNU_SOURCE

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
static volatile sig_atomic_t target_tid;
static volatile sig_atomic_t worker_signal;

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
    if (target_tid != 0 && syscall(SYS_gettid) == target_tid) {
        worker_signal = 1;
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

static void *cross_thread_worker(void *argument) {
    (void)argument;
    target_tid = syscall(SYS_gettid);
    while (!worker_signal) {
        syscall(SYS_sched_yield);
    }
    return (void *)(intptr_t)worker_signal;
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

    pthread_t worker;
    void *worker_result = 0;
    if (pthread_create(&worker, 0, cross_thread_worker, 0) != 0) {
        return 6;
    }
    while (target_tid == 0) {
        syscall(SYS_sched_yield);
    }
    if (pthread_kill(worker, SIGUSR1) != 0 || pthread_join(worker, &worker_result) != 0 ||
        worker_result != (void *)(intptr_t)1 || usr1_count != 2) {
        return 7;
    }
    target_tid = 0;

    static const char message[] = "jasper-signal-ok\n";
    if (write(STDOUT_FILENO, message, sizeof(message) - 1) !=
        (ssize_t)(sizeof(message) - 1)) {
        return 8;
    }
    return 0;
}
