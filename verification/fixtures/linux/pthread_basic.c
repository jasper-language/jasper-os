#define _GNU_SOURCE

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static atomic_int completed;
static uintptr_t shared_word;
static atomic_uint worker_tids[2];

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

    puts("jasper-pthread-ok");
    return 0;
}
