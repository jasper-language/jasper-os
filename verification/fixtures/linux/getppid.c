// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void) {
    pid_t parent = getppid();
    if (parent != 0) {
        return 2;
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
    cpu_set_t cpus;
    CPU_ZERO(&cpus);
    if (sched_getaffinity(0, sizeof(cpus), &cpus) != 0 ||
        CPU_COUNT(&cpus) < 1 || !CPU_ISSET(0, &cpus)) {
        return 11;
    }
    errno = 0;
    if (sched_getaffinity(0, 1, &cpus) != -1 || errno != EINVAL) {
        return 12;
    }
    close(fd);
    printf("jasper-ppid=%d lseek=%lld affinity=%d\n",
           (int)parent, (long long)end, CPU_COUNT(&cpus));
    return 0;
}
