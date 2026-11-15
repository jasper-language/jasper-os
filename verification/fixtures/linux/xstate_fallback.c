// Preserve XMM0-XMM15 across scheduling when the CPU exposes no AVX/XSAVE.
// 在无 AVX/XSAVE 的 CPU 上验证 XMM0-XMM15 的调度保持。
#define _GNU_SOURCE

#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define WORKERS 4
#define ROUNDS 128

static volatile int start_workers;
static volatile int failed;

static void fill_pattern(uint64_t pattern[16][2], unsigned worker,
                         unsigned round) {
    for (unsigned reg = 0; reg < 16; reg++) {
        pattern[reg][0] =
            0x4a53000000000000ULL | ((uint64_t)worker << 24) |
            ((uint64_t)reg << 8) | round;
        pattern[reg][1] =
            0xa55a000000000000ULL ^ ((uint64_t)worker << 32) ^
            ((uint64_t)reg << 4) ^ round;
    }
}

static void yield_with_xmm(const uint64_t pattern[16][2],
                           uint64_t after[16][2]) {
    __asm__ volatile(
        "movdqu 0(%[in]), %%xmm0\n"
        "movdqu 16(%[in]), %%xmm1\n"
        "movdqu 32(%[in]), %%xmm2\n"
        "movdqu 48(%[in]), %%xmm3\n"
        "movdqu 64(%[in]), %%xmm4\n"
        "movdqu 80(%[in]), %%xmm5\n"
        "movdqu 96(%[in]), %%xmm6\n"
        "movdqu 112(%[in]), %%xmm7\n"
        "movdqu 128(%[in]), %%xmm8\n"
        "movdqu 144(%[in]), %%xmm9\n"
        "movdqu 160(%[in]), %%xmm10\n"
        "movdqu 176(%[in]), %%xmm11\n"
        "movdqu 192(%[in]), %%xmm12\n"
        "movdqu 208(%[in]), %%xmm13\n"
        "movdqu 224(%[in]), %%xmm14\n"
        "movdqu 240(%[in]), %%xmm15\n"
        "mov $24, %%eax\n"
        "syscall\n"
        "movdqu %%xmm0, 0(%[out])\n"
        "movdqu %%xmm1, 16(%[out])\n"
        "movdqu %%xmm2, 32(%[out])\n"
        "movdqu %%xmm3, 48(%[out])\n"
        "movdqu %%xmm4, 64(%[out])\n"
        "movdqu %%xmm5, 80(%[out])\n"
        "movdqu %%xmm6, 96(%[out])\n"
        "movdqu %%xmm7, 112(%[out])\n"
        "movdqu %%xmm8, 128(%[out])\n"
        "movdqu %%xmm9, 144(%[out])\n"
        "movdqu %%xmm10, 160(%[out])\n"
        "movdqu %%xmm11, 176(%[out])\n"
        "movdqu %%xmm12, 192(%[out])\n"
        "movdqu %%xmm13, 208(%[out])\n"
        "movdqu %%xmm14, 224(%[out])\n"
        "movdqu %%xmm15, 240(%[out])\n"
        :
        : [in] "r"(pattern), [out] "r"(after)
        : "rax", "rcx", "r11", "memory",
          "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
          "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15");
}

static void *worker(void *opaque) {
    const unsigned worker_id = (unsigned)(uintptr_t)opaque;
    while (!__atomic_load_n(&start_workers, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }
    for (unsigned round = 0; round < ROUNDS; round++) {
        uint64_t pattern[16][2];
        uint64_t after[16][2] = {{0}};
        fill_pattern(pattern, worker_id, round);
        yield_with_xmm(pattern, after);
        for (unsigned reg = 0; reg < 16; reg++) {
            if (after[reg][0] != pattern[reg][0] ||
                after[reg][1] != pattern[reg][1]) {
                __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
                return (void *)1;
            }
        }
    }
    return NULL;
}

int main(void) {
    pthread_t threads[WORKERS];
    for (unsigned i = 0; i < WORKERS; i++) {
        if (pthread_create(&threads[i], NULL, worker,
                           (void *)(uintptr_t)i) != 0) {
            return 10;
        }
    }
    __atomic_store_n(&start_workers, 1, __ATOMIC_RELEASE);
    for (unsigned i = 0; i < WORKERS; i++) {
        void *raw = NULL;
        if (pthread_join(threads[i], &raw) != 0 || raw != NULL) {
            return 11;
        }
    }
    if (__atomic_load_n(&failed, __ATOMIC_ACQUIRE)) {
        return 12;
    }
    dprintf(STDOUT_FILENO,
            "jasper-xstate-fallback-ok workers=%d yields=%u\n",
            WORKERS, WORKERS * ROUNDS);
    return 0;
}
