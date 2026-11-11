// Verify the parent identity of a kernel-created Linux compatibility process.
// 验证内核创建的 Linux 兼容进程的父身份边界。

#include <stdio.h>
#include <unistd.h>

int main(void) {
    pid_t parent = getppid();
    if (parent != 0) {
        return 2;
    }
    printf("jasper-ppid=%d\n", (int)parent);
    return 0;
}
