#include <stdio.h>
#include <unistd.h>

int main(void)
{
    puts("jasper-sw64-toolchain-ok");
    printf("pid=%ld\n", (long)getpid());
    return 0;
}
