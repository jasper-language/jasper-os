// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。
#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    if (getenv("JASPER_EXEC_CHILD") != NULL) {
        printf("jasper-exec-child pid=%d ppid=%d\n", getpid(), getppid());
        return 0;
    }
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
    struct timespec realtime_resolution;
    struct timespec realtime_now;
    struct timeval realtime_value;
    if (clock_getres(CLOCK_REALTIME, &realtime_resolution) != 0 ||
        realtime_resolution.tv_sec != 1 ||
        realtime_resolution.tv_nsec != 0 ||
        clock_gettime(CLOCK_REALTIME, &realtime_now) != 0 ||
        gettimeofday(&realtime_value, NULL) != 0) {
        return 21;
    }
    long realtime_delta =
        (long)(realtime_value.tv_sec - realtime_now.tv_sec);
    if (realtime_now.tv_sec < 1600000000LL ||
        realtime_now.tv_sec > 4102444800LL ||
        realtime_delta < -2 || realtime_delta > 2) {
        return 21;
    }
    unsigned char random_bytes[32];
    memset(random_bytes, 0, sizeof(random_bytes));
    if (getrandom(random_bytes, sizeof(random_bytes), 0) !=
        (ssize_t)sizeof(random_bytes)) {
        return 22;
    }
    int random_nonzero = 0;
    for (unsigned i = 0; i < sizeof(random_bytes); i++) {
        random_nonzero |= random_bytes[i] != 0;
    }
    errno = 0;
    if (!random_nonzero ||
        getrandom((void *)1, 8, 0) != -1 || errno != EFAULT) {
        return 23;
    }
    printf("jasper-random-ok bytes=%u\n", (unsigned)sizeof(random_bytes));
    struct timespec before_sleep;
    struct timespec after_sleep;
    const struct timespec short_delay = {.tv_sec = 0, .tv_nsec = 20000000};
    if (clock_gettime(CLOCK_MONOTONIC, &before_sleep) != 0) {
        printf("jasper-time-fail stage=before errno=%d\n", errno);
        return 24;
    }
    if (nanosleep(&short_delay, NULL) != 0) {
        printf("jasper-time-fail stage=nanosleep errno=%d\n", errno);
        return 24;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &after_sleep) != 0) {
        printf("jasper-time-fail stage=after errno=%d\n", errno);
        return 24;
    }
    long long relative_elapsed =
        (after_sleep.tv_sec - before_sleep.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - before_sleep.tv_nsec);
    if (relative_elapsed < 10000000LL) {
        return 25;
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
        return 26;
    }
    long long absolute_elapsed =
        (after_sleep.tv_sec - absolute_deadline.tv_sec) * 1000000000LL +
        (after_sleep.tv_nsec - absolute_deadline.tv_nsec);
    if (absolute_elapsed < 0) {
        return 27;
    }
    errno = 0;
    if (nanosleep((const struct timespec *)1, NULL) != -1 || errno != EFAULT) {
        return 28;
    }
    errno = 0;
    if (syscall(SYS_clock_nanosleep, CLOCK_PROCESS_CPUTIME_ID, 0,
                &short_delay, NULL) != -1 || errno != EINVAL) {
        return 29;
    }
    DIR *root = opendir("/");
    if (root == NULL) {
        return 30;
    }
    int root_fd = dirfd(root);
    errno = 0;
    if (syscall(SYS_getdents64, root_fd, (void *)1, 256) != -1 ||
        errno != EFAULT) {
        return 31;
    }
    int saw_usr = 0;
    unsigned root_entries = 0;
    char first_root_name[256] = {0};
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(root)) != NULL) {
        if (root_entries == 0) {
            snprintf(first_root_name, sizeof(first_root_name), "%s",
                     entry->d_name);
        }
        root_entries++;
        saw_usr |= strcmp(entry->d_name, "usr") == 0;
    }
    if (errno != 0 || root_entries < 4 || !saw_usr ||
        first_root_name[0] == '\0') {
        return 32;
    }
    rewinddir(root);
    entry = readdir(root);
    if (entry == NULL || strcmp(entry->d_name, first_root_name) != 0) {
        return 33;
    }
    int usr_fd = openat(root_fd, "usr", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (usr_fd < 0) {
        return 34;
    }
    struct stat usr_stat;
    if (fstat(usr_fd, &usr_stat) != 0 || !S_ISDIR(usr_stat.st_mode)) {
        return 35;
    }
    if (fstatat(root_fd, "usr", &usr_stat, 0) != 0 ||
        !S_ISDIR(usr_stat.st_mode)) {
        return 36;
    }
    struct statx usr_statx;
    if (statx(root_fd, "usr", AT_STATX_SYNC_AS_STAT, STATX_TYPE,
              &usr_statx) != 0 || !S_ISDIR(usr_statx.stx_mode)) {
        return 37;
    }
    errno = 0;
    if (statx(AT_FDCWD, "/", AT_STATX_SYNC_AS_STAT, STATX_TYPE,
              (struct statx *)1) != -1 || errno != EFAULT) {
        return 38;
    }
    char cwd_buffer[32];
    if (chdir("/usr") != 0 ||
        getcwd(cwd_buffer, sizeof(cwd_buffer)) == NULL ||
        strcmp(cwd_buffer, "/usr") != 0) {
        return 39;
    }
    int relative_lib = openat(AT_FDCWD, "lib",
                              O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (relative_lib < 0) {
        return 40;
    }
    close(relative_lib);
    if (fchdir(root_fd) != 0 ||
        getcwd(cwd_buffer, sizeof(cwd_buffer)) == NULL ||
        strcmp(cwd_buffer, "/") != 0) {
        return 41;
    }
    close(usr_fd);
    if (closedir(root) != 0) {
        return 42;
    }
    DIR *directory = opendir("/usr/lib/x86_64-linux-gnu");
    if (directory == NULL) {
        return 43;
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
        return 44;
    }
    errno = 0;
    directory = opendir("/usr/lib/x86_64-linux-gnu/libc.so.6");
    if (directory != NULL || errno != ENOTDIR) {
        if (directory != NULL) closedir(directory);
        return 45;
    }
    struct statfs compatibility_fs;
    if (fstatfs(fd, &compatibility_fs) != 0 ||
        compatibility_fs.f_type != 0xef53 ||
        compatibility_fs.f_bsize != 4096) {
        return 44;
    }
    directory = opendir("/usr/bin");
    if (directory == NULL) {
        return 47;
    }
    unsigned executable_mask = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, "basename") == 0) executable_mask |= 1u << 0;
        if (strcmp(entry->d_name, "find") == 0) executable_mask |= 1u << 1;
        if (strcmp(entry->d_name, "ls") == 0) executable_mask |= 1u << 2;
        if (strcmp(entry->d_name, "wc") == 0) executable_mask |= 1u << 3;
    }
    if (closedir(directory) != 0 || executable_mask != 0x0fu) {
        return 48;
    }
    errno = 0;
    int executable_fd = open("/usr/bin/ls", O_RDONLY | O_CLOEXEC);
    if (executable_fd != -1 || errno != EACCES) {
        if (executable_fd >= 0) close(executable_fd);
        return 49;
    }
    errno = 0;
    executable_fd = open("/usr/bin/ls", O_RDONLY | O_CLOEXEC | O_DIRECTORY);
    if (executable_fd != -1 || errno != ENOTDIR) {
        if (executable_fd >= 0) close(executable_fd);
        return 50;
    }
    errno = 0;
    if (chdir("/usr/bin/ls") != -1 || errno != ENOTDIR) {
        return 51;
    }
    struct stat executable_stat;
    if (stat("/usr/bin/ls", &executable_stat) != 0 ||
        !S_ISREG(executable_stat.st_mode)) {
        return 52;
    }
    if ((executable_stat.st_mode & 0111) != 0111 ||
        executable_stat.st_nlink != 1 || executable_stat.st_size != 0) {
        return 53;
    }
    struct statx executable_statx;
    if (statx(AT_FDCWD, "/usr/bin/ls", AT_STATX_SYNC_AS_STAT,
              STATX_BASIC_STATS, &executable_statx) != 0 ||
        !S_ISREG(executable_statx.stx_mode) ||
        (executable_statx.stx_mode & 0111) != 0111 ||
        executable_statx.stx_nlink != 1 ||
        executable_statx.stx_size != 0) {
        return 54;
    }
    errno = 0;
    if (ioctl(STDOUT_FILENO, 0x802c542aUL, NULL) != -1 || errno != ENOTTY) {
        return 45;
    }
    if (sched_getscheduler(0) != SCHED_OTHER) {
        return 46;
    }
    pid_t fork_parent_pid = getpid();
    volatile int fork_private = 0x1234;
    pid_t first_child = fork();
    if (first_child < 0) {
        return 59;
    }
    if (first_child == 0) {
        _exit(6);
    }
    pid_t child = fork();
    if (child < 0) {
        printf("jasper-fork-fail errno=%d\n", errno);
        return 55;
    }
    if (child == 0) {
        if (getppid() != fork_parent_pid) {
            _exit(8);
        }
        fork_private = 0x5678;
        _exit(7);
    }
    int child_status = 0;
    if (waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 7) {
        return 56;
    }
    if (fork_private != 0x1234) {
        return 57;
    }
    child_status = 0;
    if (waitpid(first_child, &child_status, 0) != first_child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 6) {
        return 60;
    }
    errno = 0;
    if (waitpid(child, &child_status, 0) != -1 || errno != ECHILD) {
        return 58;
    }
    pid_t any_a = fork();
    if (any_a < 0) {
        return 62;
    }
    if (any_a == 0) {
        _exit(9);
    }
    pid_t any_b = fork();
    if (any_b < 0) {
        return 63;
    }
    if (any_b == 0) {
        _exit(10);
    }
    int saw_nine = 0;
    int saw_ten = 0;
    for (int i = 0; i < 2; i++) {
        child_status = 0;
        pid_t reaped = waitpid(-1, &child_status, 0);
        if (reaped != any_a && reaped != any_b) {
            return 64;
        }
        if (!WIFEXITED(child_status)) {
            return 65;
        }
        int code = WEXITSTATUS(child_status);
        saw_nine |= code == 9;
        saw_ten |= code == 10;
    }
    if (!saw_nine || !saw_ten) {
        return 66;
    }
    errno = 0;
    if (waitpid(-1, &child_status, WNOHANG) != -1 || errno != ECHILD) {
        return 67;
    }
    close(fd);
    printf("jasper-ppid=%d lseek=%lld affinity=%d cpu=%u node=%u uptime=%lld totalram=%llu freeram=%llu procs=%u exe=%s resolution_ns=%ld sleep_ns=%lld wall=%lld dirent=6 exec_meta=true fork=true\n",
           (int)parent, (long long)end, CPU_COUNT(&cpus), cpu, node,
           (long long)info.uptime, (unsigned long long)info.totalram,
           (unsigned long long)info.freeram, (unsigned)info.procs, executable,
           resolution.tv_nsec, relative_elapsed, (long long)realtime_now.tv_sec);
    printf("jasper-exec-before pid=%d ppid=%d\n", getpid(), getppid());
    fflush(stdout);
    char *exec_argv[] = {"/usr/bin/jasper-getppid", NULL};
    char *exec_envp[] = {"JASPER_EXEC_CHILD=1", NULL};
    execve(exec_argv[0], exec_argv, exec_envp);
    printf("jasper-exec-fail errno=%d\n", errno);
    return 61;
}
