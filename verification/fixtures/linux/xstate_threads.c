// Preserve YMM0-YMM15 across repeated scheduling and cross-CPU migration.
// 在真实调度与跨 CPU 迁移中逐位验证 YMM0-YMM15。
#define _GNU_SOURCE

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

#define WORKERS 4
#define ROUNDS 256

static int allowed[CPU_SETSIZE];
static int allowed_count;
static volatile int start_workers;
static volatile int failed;

struct worker_result {
    unsigned observed_cpu_mask;
    unsigned transitions;
};

static void fill_pattern(uint64_t pattern[16][4], unsigned worker,
                         unsigned round) {
    for (unsigned reg = 0; reg < 16; reg++) {
        uint64_t base = 0x4a53000000000000ULL |
                        ((uint64_t)worker << 40) |
                        ((uint64_t)reg << 32) |
                        round;
        for (unsigned lane = 0; lane < 4; lane++) {
            pattern[reg][lane] = base ^
                (0x9e3779b97f4a7c15ULL * (lane + 1));
        }
    }
}

static void yield_with_ymm(const uint64_t pattern[16][4],
                           uint64_t after[16][4]) {
    __asm__ volatile(
        "vmovdqu 0(%[in]), %%ymm0\n"
        "vmovdqu 32(%[in]), %%ymm1\n"
        "vmovdqu 64(%[in]), %%ymm2\n"
        "vmovdqu 96(%[in]), %%ymm3\n"
        "vmovdqu 128(%[in]), %%ymm4\n"
        "vmovdqu 160(%[in]), %%ymm5\n"
        "vmovdqu 192(%[in]), %%ymm6\n"
        "vmovdqu 224(%[in]), %%ymm7\n"
        "vmovdqu 256(%[in]), %%ymm8\n"
        "vmovdqu 288(%[in]), %%ymm9\n"
        "vmovdqu 320(%[in]), %%ymm10\n"
        "vmovdqu 352(%[in]), %%ymm11\n"
        "vmovdqu 384(%[in]), %%ymm12\n"
        "vmovdqu 416(%[in]), %%ymm13\n"
        "vmovdqu 448(%[in]), %%ymm14\n"
        "vmovdqu 480(%[in]), %%ymm15\n"
        "mov $24, %%eax\n"
        "syscall\n"
        "vmovdqu %%ymm0, 0(%[out])\n"
        "vmovdqu %%ymm1, 32(%[out])\n"
        "vmovdqu %%ymm2, 64(%[out])\n"
        "vmovdqu %%ymm3, 96(%[out])\n"
        "vmovdqu %%ymm4, 128(%[out])\n"
        "vmovdqu %%ymm5, 160(%[out])\n"
        "vmovdqu %%ymm6, 192(%[out])\n"
        "vmovdqu %%ymm7, 224(%[out])\n"
        "vmovdqu %%ymm8, 256(%[out])\n"
        "vmovdqu %%ymm9, 288(%[out])\n"
        "vmovdqu %%ymm10, 320(%[out])\n"
        "vmovdqu %%ymm11, 352(%[out])\n"
        "vmovdqu %%ymm12, 384(%[out])\n"
        "vmovdqu %%ymm13, 416(%[out])\n"
        "vmovdqu %%ymm14, 448(%[out])\n"
        "vmovdqu %%ymm15, 480(%[out])\n"
        :
        : [in] "r"(pattern), [out] "r"(after)
        : "rax", "rcx", "r11", "memory",
          "ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7",
          "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15");
}

static int pin_to_cpu(int cpu) {
    uint64_t set = 1ULL << cpu;
    return (int)syscall(SYS_sched_setaffinity, 0, sizeof(set), &set);
}

static int current_cpu(void) {
    uint32_t cpu = 0xffffffffU;
    if (syscall(SYS_getcpu, &cpu, NULL, NULL) != 0) {
        return -1;
    }
    return (int)cpu;
}

static void *worker(void *opaque) {
    const unsigned worker_id = (unsigned)(uintptr_t)opaque;
    struct worker_result result = {0, 0};
    __atomic_store_n(&result.transitions, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&result.observed_cpu_mask, 0, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&start_workers, __ATOMIC_ACQUIRE)) {
        sched_yield();
    }

    int previous_cpu = -1;
    for (unsigned round = 0; round < ROUNDS; round++) {
        const unsigned passes = allowed_count > 1 ? 2 : 1;
        for (unsigned pass = 0; pass < passes; pass++) {
            const unsigned sample = round * passes + pass;
            const int cpu =
                allowed[(worker_id + sample) % (unsigned)allowed_count];
            if (pin_to_cpu(cpu) != 0) {
                __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
                return (void *)1;
            }
            uint64_t pattern[16][4];
            uint64_t after[16][4];
            fill_pattern(pattern, worker_id, sample);
            for (unsigned i = 0; i < 16 * 4; i++) {
                after[i / 4][i % 4] = 0;
            }
            yield_with_ymm(pattern, after);
            for (unsigned reg = 0; reg < 16; reg++) {
                for (unsigned lane = 0; lane < 4; lane++) {
                    if (after[reg][lane] != pattern[reg][lane]) {
                        __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
                        return (void *)2;
                    }
                }
            }
            const int observed_cpu = current_cpu();
            if (observed_cpu < 0 || observed_cpu >= 32) {
                __atomic_store_n(&failed, 1, __ATOMIC_RELEASE);
                return (void *)3;
            }
            result.observed_cpu_mask |= 1U << observed_cpu;
            if (previous_cpu >= 0 && previous_cpu != observed_cpu) {
                result.transitions++;
            }
            previous_cpu = observed_cpu;
        }
    }
    return (void *)(uintptr_t)(
        ((unsigned)result.observed_cpu_mask << 8) |
        (result.transitions & 0xff));
}

int main(void) {
    uint64_t initial = 0;
    if (syscall(SYS_sched_getaffinity, 0, sizeof(initial), &initial) < 0) {
        return 10;
    }
    for (int cpu = 0; cpu < 64; cpu++) {
        if (initial & (1ULL << cpu)) {
            allowed[allowed_count++] = cpu;
        }
    }
    if (allowed_count == 0) {
        return 11;
    }

    pthread_t threads[WORKERS];
    for (unsigned i = 0; i < WORKERS; i++) {
        if (pthread_create(&threads[i], NULL, worker,
                           (void *)(uintptr_t)i) != 0) {
            return 12;
        }
    }
    __atomic_store_n(&start_workers, 1, __ATOMIC_RELEASE);

    unsigned observed = 0;
    unsigned transitions = 0;
    int every_worker_migrated = 1;
    for (unsigned i = 0; i < WORKERS; i++) {
        void *raw = NULL;
        if (pthread_join(threads[i], &raw) != 0) {
            return 13;
        }
        const unsigned packed = (unsigned)(uintptr_t)raw;
        dprintf(STDOUT_FILENO,
                "[JSR-XSTATE-WORKER] worker=%u packed=0x%x\n", i, packed);
        if (packed > 0 && packed <= 3) {
            return 15;
        }
        observed |= packed >> 8;
        transitions += packed & 0xff;
        if (allowed_count > 1 &&
            __builtin_popcount(packed >> 8) < 2) {
            every_worker_migrated = 0;
        }
    }
    if (__atomic_load_n(&failed, __ATOMIC_ACQUIRE) ||
        !every_worker_migrated) {
        return 14;
    }
    dprintf(STDOUT_FILENO,
            "jasper-xstate-matrix-ok workers=%d cpus=%d observed=0x%x "
            "transitions=%u yields=%u\n",
            WORKERS, allowed_count, observed, transitions,
            WORKERS * ROUNDS * (allowed_count > 1 ? 2 : 1));
    (void)errno;
    return 0;
}
