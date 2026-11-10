#define _GNU_SOURCE

#include <pthread.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static atomic_int completed;
static uintptr_t shared_word;
static atomic_uint worker_tids[2];
static pthread_mutex_t robust_mutex;

static void *worker(void *argument) {
    uintptr_t marker = (uintptr_t)argument;
    unsigned index = marker == UINT64_C(0x100) ? 0 : 1;
    atomic_store_explicit(&worker_tids[index], (unsigned)syscall(SYS_gettid),
                          memory_order_release);
    pthread_mutex_lock(&mutex);
    shared_word |= marker;
    atomic_fetch_add_explicit(&completed, 1, memory_order_release);
    pthread_cond_signal(&condition);
    pthread_mutex_unlock(&mutex);
    return (void *)(marker ^ UINT64_C(0x55aa55aa));
}

static void *robust_owner(void *argument) {
    (void)argument;
    if (pthread_mutex_lock(&robust_mutex) != 0) {
        return (void *)UINT64_C(1);
    }
    pthread_exit((void *)UINT64_C(0x700));
}

int main(void) {
    pthread_t first;
    pthread_t second;
    void *first_result = 0;
    void *second_result = 0;
    int create_error;

    create_error = pthread_create(&first, 0, worker, (void *)UINT64_C(0x100));
    if (create_error == 0) {
        create_error = pthread_create(&second, 0, worker, (void *)UINT64_C(0x200));
    }
    if (create_error != 0) {
        printf("pthread-create-failed:%d\n", create_error);
        return 10;
    }

    pthread_mutex_lock(&mutex);
    while (atomic_load_explicit(&completed, memory_order_acquire) != 2) {
        pthread_cond_wait(&condition, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    if (pthread_join(first, &first_result) != 0 ||
        pthread_join(second, &second_result) != 0) {
        puts("pthread-join-failed");
        return 11;
    }

    uintptr_t expected = UINT64_C(0x100) | UINT64_C(0x200);
    unsigned leader_tid = (unsigned)syscall(SYS_gettid);
    unsigned first_tid = atomic_load_explicit(&worker_tids[0], memory_order_acquire);
    unsigned second_tid = atomic_load_explicit(&worker_tids[1], memory_order_acquire);
    if (shared_word != expected ||
        leader_tid == 0 || first_tid == 0 || second_tid == 0 ||
        leader_tid == first_tid || leader_tid == second_tid || first_tid == second_tid ||
        first_result != (void *)(UINT64_C(0x100) ^ UINT64_C(0x55aa55aa)) ||
        second_result != (void *)(UINT64_C(0x200) ^ UINT64_C(0x55aa55aa))) {
        puts("pthread-result-mismatch");
        return 12;
    }

    pthread_mutexattr_t attributes;
    pthread_t robust_thread;
    void *robust_result = 0;
    if (pthread_mutexattr_init(&attributes) != 0 ||
        pthread_mutexattr_setrobust(&attributes, PTHREAD_MUTEX_ROBUST) != 0 ||
        pthread_mutex_init(&robust_mutex, &attributes) != 0 ||
        pthread_create(&robust_thread, 0, robust_owner, 0) != 0 ||
        pthread_join(robust_thread, &robust_result) != 0 ||
        robust_result != (void *)UINT64_C(0x700)) {
        puts("pthread-robust-setup-failed");
        return 13;
    }
    int robust_lock = pthread_mutex_lock(&robust_mutex);
    if (robust_lock != EOWNERDEAD ||
        pthread_mutex_consistent(&robust_mutex) != 0 ||
        pthread_mutex_unlock(&robust_mutex) != 0) {
        printf("pthread-robust-failed:%d\n", robust_lock);
        return 14;
    }

    unsigned char random_first[32];
    unsigned char random_second[32];
    if (getrandom(random_first, sizeof(random_first), GRND_NONBLOCK) !=
            (ssize_t)sizeof(random_first) ||
        getrandom(random_second, sizeof(random_second), GRND_NONBLOCK) !=
            (ssize_t)sizeof(random_second)) {
        puts("getrandom-failed");
        return 15;
    }
    int random_nonzero = 0;
    int random_equal = 1;
    for (size_t index = 0; index < sizeof(random_first); index++) {
        random_nonzero |= random_first[index] != 0;
        random_equal &= random_first[index] == random_second[index];
    }
    if (!random_nonzero || random_equal) {
        puts("getrandom-deterministic");
        return 16;
    }

    puts("jasper-pthread-ok");
    return 0;
}
