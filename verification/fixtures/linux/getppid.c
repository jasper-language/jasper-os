// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/uio.h>
#include <time.h>
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
    unsigned cpu = UINT32_MAX;
    unsigned node = UINT32_MAX;
    if (syscall(SYS_getcpu, &cpu, &node, NULL) != 0 ||
        cpu >= CPU_SETSIZE || !CPU_ISSET(cpu, &cpus) || node != 0) {
        return 13;
    }
    errno = 0;
    if (syscall(SYS_getcpu, (void *)1, NULL, NULL) != -1 || errno != EFAULT) {
        return 14;
    }
    char executable[128];
    ssize_t executable_len = readlinkat(AT_FDCWD, "/proc/self/exe",
                                       executable, sizeof(executable) - 1);
    if (executable_len <= 0 ||
        (size_t)executable_len >= sizeof(executable) - 1) {
        return 15;
    }
    executable[executable_len] = '\0';
    if (strcmp(executable, "/usr/bin/jasper-getppid") != 0) {
        return 16;
    }
    errno = 0;
    if (readlinkat(AT_FDCWD, "/not-in-compat-root",
                   executable, sizeof(executable)) != -1 || errno != ENOENT) {
        return 17;
    }
    struct sysinfo info;
    if (sysinfo(&info) != 0 || info.uptime < 0 || info.totalram == 0 ||
        info.freeram == 0 || info.freeram > info.totalram || info.mem_unit == 0 ||
        info.procs == 0 || info.totalswap != 0 || info.freeswap != 0) {
        return 18;
    }
    errno = 0;
    if (syscall(SYS_sysinfo, (void *)1) != -1 || errno != EFAULT) {
        return 19;
    }
    struct timespec resolution;
    if (clock_getres(CLOCK_MONOTONIC, &resolution) != 0 ||
        resolution.tv_sec < 0 || resolution.tv_nsec <= 0 ||
        resolution.tv_nsec >= 1000000000L) {
        return 20;
    }
    struct timespec before_sleep;
    struct timespec after_sleep;
    const struct timespec short_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (clock_gettime(CLOCK_MONOTONIC, &before_sleep) != 0) {
        printf("jasper-time-fail stage=before errno=%d\n", errno);
        return 21;
    }
    if (nanosleep(&short_delay, NULL) != 0) {
        printf("jasper-time-fail stage=nanosleep errno=%d\n", errno);
        return 21;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after_sleep) != 0) {
        printf("jasper-time-fail stage=after errno=%d\n", errno);
        return 21;
    }
    long long relative_elapsed =
        (after_sleep.tv_sec - before_sleep.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - before_sleep.tv_nsec);
    if (relative_elapsed < 10000000LL) {
        return 22;
    }
    struct timespec absolute_deadline = after_sleep;
    absolute_deadline.tv_nsec += 10000000L;
    if (absolute_deadline.tv_nsec >= 1000000000L) {
        absolute_deadline.tv_sec += 1;
        absolute_deadline.tv_nsec -= 1000000000L;
    }
    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME,
                        &absolute_deadline, NULL) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &after_sleep) != 0) {
        return 23;
    }
    long long absolute_elapsed =
        (after_sleep.tv_sec - absolute_deadline.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - absolute_deadline.tv_nsec);
    if (absolute_elapsed < 0) {
        return 24;
    }
    errno = 0;
    if (nanosleep((const struct timespec *)1, NULL) != -1 || errno != EFAULT) {
        return 25;
    }
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_PROCESS_CPUTIME_ID, 0,
                &short_delay, NULL) != -1 || errno != EINVAL) {
        return 26;
    }
    DIR *root = opendir("/");
    if (root == NULL) {
        return 27;
    }
    int root_fd = dirfd(root);
    errno = 0;
    if (syscall(SYS_getdents64, root_fd, (void *)1, 256) != -1 ||
        errno != EFAULT) {
        return 28;
    }
    int saw_usr = 0;
    unsigned root_entries = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(root)) != NULL) {
        root_entries++;
        saw_usr |= strcmp(entry->d_name, "usr") == 0;
    }
    if (errno != 0 || root_entries < 4 || !saw_usr) {
        return 29;
    }
    int usr_fd = openat(root_fd, "usr", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (usr_fd < 0) {
        return 30;
    }
    struct stat usr_stat;
    if (fstat(usr_fd, &usr_stat) != 0 || !S_ISDIR(usr_stat.st_mode)) {
        return 31;
    }
    if (fstatat(root_fd, "usr", &usr_stat, 0) != 0 ||
        !S_ISDIR(usr_stat.st_mode)) {
        return 32;
    }
    close(usr_fd);
    if (closedir(root) != 0) {
        return 33;
    }
    DIR *directory = opendir("/usr/lib/x86_64-linux-gnu");
    if (directory == NULL) {
        return 34;
    }
    unsigned library_mask = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "libc.so.6") == 0) library_mask |= 1u << 0;
        if (strcmp(entry->d_name, "libsystemd.so.0") == 0) library_mask |= 1u << 1;
        if (strcmp(entry->d_name, "libselinux.so.1") == 0) library_mask |= 1u << 2;
        if (strcmp(entry->d_name, "libgcc_s.so.1") == 0) library_mask |= 1u << 3;
        if (strcmp(entry->d_name, "libm.so.6") == 0) library_mask |= 1u << 4;
        if (strcmp(entry->d_name, "libpcre2-8.so.0") == 0) library_mask |= 1u << 5;
    }
    if (closedir(directory) != 0 || library_mask != 0x3fu) {
        return 35;
    }
    errno = 0;
    directory = opendir("/usr/lib/x86_64-linux-gnu/libc.so.6");
    if (directory != NULL || errno != ENOTDIR) {
        if (directory != NULL) closedir(directory);
        return 36;
    }
    close(fd);
    printf("jasper-ppid=%d lseek=%lld affinity=%d cpu=%u node=%u uptime=%lld totalram=%llu freeram=%llu procs=%u exe=%s resolution_ns=%ld sleep_ns=%lld dirent=6\n",
           (int)parent, (long long)end, CPU_COUNT(&cpus), cpu, node,
           (long long)info.uptime, (unsigned long long)info.totalram,
           (unsigned long long)info.freeram, (unsigned)info.procs, executable,
           resolution.tv_nsec, relative_elapsed);
    return 0;
}
