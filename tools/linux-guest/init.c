typedef unsigned long usize;

static long syscall1(long number, long a1) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a1)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall3(long number, long a1, long a2, long a3) {
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a1), "S"(a2), "d"(a3)
                     : "rcx", "r11", "memory");
    return result;
}

static long syscall5(long number, long a1, long a2, long a3, long a4, long a5) {
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a1), "S"(a2), "d"(a3), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return result;
}

static unsigned char inb(unsigned short port) {
    unsigned char value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static unsigned short inw(unsigned short port) {
    unsigned short value;
    __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static unsigned int inl(unsigned short port) {
    unsigned int value;
    __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void outb(unsigned short port, unsigned char value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static void write_all(long fd, const char *data, usize len) {
    while (len != 0) {
        long written = syscall3(1, fd, (long)data, (long)len);
        if (written <= 0)
            return;
        data += written;
        len -= (usize)written;
    }
}

__attribute__((noreturn)) void _start(void) {
    static const char dev[] = "/dev";
    static const char devtmpfs[] = "devtmpfs";
    static const char kmsg_path[] = "/dev/kmsg";
    static const char console_path[] = "/dev/console";
    static const char hwrng_path[] = "/dev/hwrng";
    static const char hvc_path[] = "/dev/hvc0";
    static const char block_path[] = "/dev/vda";
    static const char base_marker[] =
        "<2>[JSR-LINUX-GUEST] init=true arch=x86_64 syscall=true\n";
    static const char rng_marker[] = "<2>[JSR-VIRTIO] device=rng ok=true\n";
    static const char console_marker[] = "<2>[JSR-VIRTIO] device=console ok=true\n";
    static const char block_marker[] = "<2>[JSR-VIRTIO] device=block ok=true\n";
    static const char pio_marker[] =
        "<2>[JSR-HWV5-PIO] device=jpio discovered=true ping=true reset=true pending=true cancel=true generation=2 writes=0 ok=true\n";
    static const unsigned char block_expected[16] = "JASPER-BLOCK-001";
    unsigned char block_data[16];
    unsigned char random[8];
    int rng_ok;
    int console_ok;
    int block_ok;
    int pio_ok;
    long fd;
    long hvc;

    (void)syscall5(165, (long)devtmpfs, (long)dev, (long)devtmpfs, 0, 0);
    rng_ok = syscall3(2, (long)hwrng_path, 0, 0);
    if (rng_ok >= 0)
        rng_ok = syscall3(0, rng_ok, (long)random, sizeof(random)) > 0;
    hvc = syscall3(2, (long)hvc_path, 1, 0);
    console_ok = hvc >= 0;
    block_ok = 0;
    fd = syscall3(2, (long)block_path, 0, 0);
    if (fd >= 0 && syscall3(0, fd, (long)block_data, sizeof(block_data)) == sizeof(block_data)) {
        block_ok = 1;
        for (usize i = 0; i < sizeof(block_expected); ++i) {
            if (block_data[i] != block_expected[i])
                block_ok = 0;
        }
    }
    pio_ok = 0;
    if (syscall3(173, 0x500, 32, 1) == 0) {
        unsigned int control = inl(0x500);
        unsigned short status = inw(0x504);
        unsigned short generation = inw(0x506);
        if ((control & 0xffffU) == 0x4f49504aU
            && (control >> 16) == 0x50490001U
            && (status & 1U) != 0
            && generation == 1) {
            outb(0x508, 2);
            if (inl(0x50c) == 1) {
                outb(0x508, 1);
                if (inw(0x506) == 2 && inl(0x50c) == 0) {
                    outb(0x508, 3);
                    if ((inw(0x504) & 3U) == 3U) {
                        outb(0x508, 4);
                        if ((inw(0x504) & 5U) == 5U
                            && inl(0x510) == 1
                            && inl(0x514) == 1)
                            pio_ok = 1;
                    }
                }
            }
        }
    }
    fd = syscall3(2, (long)kmsg_path, 1, 0);
    if (fd >= 0) {
        write_all(fd, base_marker, sizeof(base_marker) - 1);
        if (rng_ok)
            write_all(fd, rng_marker, sizeof(rng_marker) - 1);
        if (console_ok)
            write_all(fd, console_marker, sizeof(console_marker) - 1);
        if (block_ok)
            write_all(fd, block_marker, sizeof(block_marker) - 1);
        if (pio_ok)
            write_all(fd, pio_marker, sizeof(pio_marker) - 1);
        if (console_ok)
            write_all(hvc, console_marker, sizeof(console_marker) - 1);
    }
    fd = syscall3(2, (long)console_path, 1, 0);
    if (fd >= 0) {
        write_all(fd, base_marker, sizeof(base_marker) - 1);
        if (pio_ok)
            write_all(fd, pio_marker, sizeof(pio_marker) - 1);
    }
    for (;;)
        (void)syscall1(34, 0);
}
