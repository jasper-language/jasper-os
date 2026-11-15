// Exercise hostile Linux rt_sigreturn XSAVE frames and one valid restore.
// 验证恶意 rt_sigreturn XSAVE 映像失败关闭，并保留合法完整恢复。
#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#define FRAME_BYTES 1024
#define FPSTATE_BYTES 4096
#define UC_GREGS 40
#define UC_FPREGS 224
#define UC_SIGMASK 296
#define GREG_RSP 15
#define GREG_RIP 16
#define XSTATE_BV_OFFSET 512
#define XCOMP_BV_OFFSET 520
#define HEADER_RESERVED_OFFSET 528
#define MXCSR_OFFSET 24

static unsigned char frame[FRAME_BYTES] __attribute__((aligned(64)));
static unsigned char baseline[FPSTATE_BYTES] __attribute__((aligned(64)));
static unsigned char fpstate[FPSTATE_BYTES] __attribute__((aligned(64)));
static unsigned char valid_stack[16 * 1024] __attribute__((aligned(16)));

static void put64(size_t offset, uint64_t value) {
    memcpy(frame + offset, &value, sizeof(value));
}

static void put_fp64(size_t offset, uint64_t value) {
    memcpy(fpstate + offset, &value, sizeof(value));
}

static void restore_success(void) __attribute__((noreturn, noinline));

static void restore_success(void) {
    static const char message[] = "jasper-sigreturn-xstate-ok\n";
    if (write(STDOUT_FILENO, message, sizeof(message) - 1) !=
        (ssize_t)(sizeof(message) - 1)) {
        _exit(71);
    }
    syscall(SYS_exit, 0);
    __builtin_unreachable();
}

static void capture_xstate(void) {
    uint32_t low;
    uint32_t high;
    __asm__ volatile("xgetbv" : "=a"(low), "=d"(high) : "c"(0));
    if ((low & 0x3) != 0x3) {
        _exit(72);
    }
    (void)high;
    memset(baseline, 0, sizeof(baseline));
    __asm__ volatile(
        "xsave64 (%[state])"
        :
        : [state] "r"(baseline), "a"(~0U), "d"(~0U)
        : "memory");
}

static void reset_frame(void) {
    memcpy(fpstate, baseline, sizeof(fpstate));
    memset(frame, 0, sizeof(frame));
    const uint64_t stack_top =
        ((uintptr_t)valid_stack + sizeof(valid_stack)) & ~(uintptr_t)0xf;
    put64(UC_GREGS + GREG_RSP * 8, stack_top - 8);
    put64(UC_GREGS + GREG_RIP * 8, (uintptr_t)restore_success);
    put64(UC_GREGS + 13 * 8, 0);
    put64(UC_FPREGS, (uintptr_t)fpstate);
    put64(UC_SIGMASK, 0);
}

static long invoke_rt_sigreturn(void *raw_frame) {
    long result;
    __asm__ volatile(
        "mov %%rsp, %%r8\n"
        "mov %[frame], %%rsp\n"
        "mov $15, %%rax\n"
        "syscall\n"
        "mov %%r8, %%rsp\n"
        : "=a"(result)
        : [frame] "r"(raw_frame)
        : "rcx", "r8", "r11", "memory");
    return result;
}

static int mask_is_unchanged(void) {
    sigset_t current;
    if (sigprocmask(SIG_SETMASK, NULL, &current) != 0) {
        return 0;
    }
    return sigismember(&current, SIGUSR1) == 1 &&
           sigismember(&current, SIGTERM) == 0;
}

static int expect_invalid(const char *name, long expected, void *raw_frame) {
    const long result = invoke_rt_sigreturn(raw_frame);
    const int unchanged = mask_is_unchanged();
    dprintf(STDOUT_FILENO,
            "[JSR-SIGRETURN-NEGATIVE] case=%s result=%ld expected=%ld "
            "mask_unchanged=%s\n",
            name, result, expected, unchanged ? "true" : "false");
    return result == expected && unchanged;
}

int main(int argc, char **argv) {
    capture_xstate();

    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL) != 0) {
        _exit(73);
    }

    reset_frame();
    put_fp64(XSTATE_BV_OFFSET, 1ULL << 63);
    if (!expect_invalid("xstate_bv_disabled", -EINVAL, frame)) {
        _exit(74);
    }

    reset_frame();
    put_fp64(XSTATE_BV_OFFSET, 0x2);
    if (!expect_invalid("missing_x87", -EINVAL, frame)) {
        _exit(75);
    }

    reset_frame();
    put_fp64(XCOMP_BV_OFFSET, 1ULL << 63);
    if (!expect_invalid("compact_format", -EINVAL, frame)) {
        _exit(76);
    }

    reset_frame();
    put_fp64(XCOMP_BV_OFFSET, 1);
    if (!expect_invalid("reserved_xcomp_bv", -EINVAL, frame)) {
        _exit(77);
    }

    reset_frame();
    fpstate[HEADER_RESERVED_OFFSET] = 1;
    if (!expect_invalid("reserved_header", -EINVAL, frame)) {
        _exit(78);
    }

    reset_frame();
    const uint32_t bad_mxcsr = 0x00010000U;
    memcpy(fpstate + MXCSR_OFFSET, &bad_mxcsr, sizeof(bad_mxcsr));
    if (!expect_invalid("mxcsr_reserved", -EINVAL, frame)) {
        _exit(79);
    }

    reset_frame();
    put64(UC_FPREGS, 1);
    if (!expect_invalid("fpstate_oob", -EFAULT, frame)) {
        _exit(80);
    }

    if (argc > 1 && strcmp(argv[1], "--invalid-only") == 0) {
        return 0;
    }

    reset_frame();
    static const char valid_message[] = "jasper-sigreturn-xstate-valid-invoke\n";
    if (write(STDOUT_FILENO, valid_message, sizeof(valid_message) - 1) !=
        (ssize_t)(sizeof(valid_message) - 1)) {
        _exit(81);
    }
    (void)invoke_rt_sigreturn(frame);
    _exit(82);
}
