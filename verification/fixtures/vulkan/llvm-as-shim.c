/*
 * Verification-only llvm-as fixture for the upstream Metal2Vulkan examples.
 *
 * The examples invoke `llvm-as -o - <runtime_examples.ll>` when no metallib
 * argument is supplied. Jasper-OS stages the upstream fixture's preassembled
 * AIR bitcode, so this freestanding static PIE writes those exact bytes to
 * stdout. It deliberately uses only raw Linux syscalls, keeping the fixture
 * independent of the host C runtime.
 */

typedef unsigned long usize;
typedef long isize;

static const char AIR_PATH[] =
    "/usr/lib/x86_64-linux-gnu/runtime_examples.air";

static long syscall1(long number, long arg0)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(arg0)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall3(long number, long arg0, long arg1, long arg2)
{
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(arg0), "S"(arg1), "d"(arg2)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long arg0, long arg1, long arg2, long arg3)
{
    register long arg4 __asm__("r10") = arg3;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(arg0), "S"(arg1), "d"(arg2),
                       "r"(arg4)
                     : "rcx", "r11", "memory");
    return result;
}

static void write_all(const unsigned char *bytes, usize length)
{
    while (length != 0) {
        long written = syscall3(1, 1, (long)bytes, (long)length);
        if (written <= 0) {
            return;
        }
        bytes += (usize)written;
        length -= (usize)written;
    }
}

static isize c_string_length(const char *text)
{
    isize length = 0;
    while (text[length] != 0) {
        ++length;
    }
    return length;
}

__attribute__((noreturn)) void _start(void)
{
    long fd = syscall4(257, -100, (long)AIR_PATH, 0, 0);
    if (fd < 0) {
        const char message[] = "llvm-as fixture: open AIR failed\n";
        write_all((const unsigned char *)message,
                  (usize)c_string_length(message));
        syscall1(231, 1);
    }

    unsigned char buffer[4096];
    for (;;) {
        long count = syscall3(0, fd, (long)buffer, (long)sizeof(buffer));
        if (count < 0) {
            const char message[] = "llvm-as fixture: read AIR failed\n";
            write_all((const unsigned char *)message,
                      (usize)c_string_length(message));
            syscall1(231, 1);
        }
        if (count == 0) {
            break;
        }
        write_all(buffer, (usize)count);
    }
    syscall1(3, fd);
    syscall1(231, 0);
    for (;;) {
    }
}
