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

static long syscall6(long number, long a1, long a2, long a3, long a4, long a5,
                     long a6) {
    register long r10 __asm__("r10") = a4;
    register long r8 __asm__("r8") = a5;
    register long r9 __asm__("r9") = a6;
    long result;
    __asm__ volatile("syscall"
                     : "=a"(result)
                     : "a"(number), "D"(a1), "S"(a2), "d"(a3), "r"(r10),
                       "r"(r8), "r"(r9)
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

static void write_cstr(long fd, const char *data) {
    usize len = 0;
    while (data[len] != '\0')
        ++len;
    write_all(fd, data, len);
}

static void write_decimal(long fd, unsigned long value) {
    char digits[24];
    usize len = 0;
    do {
        digits[len++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (len != 0) {
        --len;
        write_all(fd, &digits[len], 1);
    }
}

struct sockaddr_ll {
    unsigned short family;
    unsigned short protocol;
    int ifindex;
    unsigned short hatype;
    unsigned char pkttype;
    unsigned char halen;
    unsigned char address[8];
};

static void zero_bytes(unsigned char *bytes, usize len) {
    for (usize i = 0; i < len; ++i)
        bytes[i] = 0;
}

static int ifreq_ioctl(int fd, unsigned long request, char ifr[40]) {
    zero_bytes((unsigned char *)ifr, 40);
    ifr[0] = 'e';
    ifr[1] = 't';
    ifr[2] = 'h';
    ifr[3] = '0';
    return (int)syscall3(16, fd, (long)request, (long)ifr);
}

static int ifreq_ioctl_prepared(int fd, unsigned long request, char ifr[40]) {
    return (int)syscall3(16, fd, (long)request, (long)ifr);
}

static int net_stage;
static int fs_stage;
static long net_error;
static long net_set_error;
static int net_flags;
static long fs_write_result;
static long fs_readback_result;

static int arp_roundtrip(int *tx_ok, int *rx_ok) {
    static const unsigned char expected_ip[4] = {10, 0, 2, 2};
    unsigned char request[42];
    unsigned char reply[128];
    unsigned char local_mac[6] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x57};
    char ifr[40];
    struct sockaddr_ll address;
    long inet;
    long packet;
    int ifindex;

    inet = syscall3(41, 2, 2, 0);
    if (inet < 0)
        return 0;
    net_stage = 1;
    if (ifreq_ioctl((int)inet, 0x8933, ifr) < 0) {
        (void)syscall1(3, inet);
        return 0;
    }
    ifindex = *(int *)(ifr + 16);
    net_stage = 2;
    if (ifindex <= 0 || ifreq_ioctl((int)inet, 0x8913, ifr) < 0) {
        (void)syscall1(3, inet);
        return 0;
    }
    net_stage = 3;
    *(unsigned short *)(ifr + 16) |= 1;
    net_set_error = ifreq_ioctl_prepared((int)inet, 0x8914, ifr);
    if (net_set_error < 0) {
        (void)syscall1(3, inet);
        return 0;
    }
    net_stage = 3;
    if (ifreq_ioctl((int)inet, 0x8913, ifr) < 0)
        return 0;
    net_flags = *(unsigned short *)(ifr + 16);
    if ((net_flags & 1) == 0)
        return 0;
    if (ifreq_ioctl((int)inet, 0x8927, ifr) == 0) {
        for (usize i = 0; i < 6; ++i)
            local_mac[i] = (unsigned char)ifr[18 + i];
    }
    (void)syscall1(3, inet);

    packet = syscall3(41, 17, 3, 0x0608);
    if (packet < 0)
        return 0;
    net_stage = 4;
    zero_bytes((unsigned char *)&address, sizeof(address));
    address.family = 17;
    address.protocol = 0x0608;
    address.ifindex = ifindex;
    address.halen = 6;
    for (usize i = 0; i < 6; ++i)
        address.address[i] = local_mac[i];
    if (syscall3(49, packet, (long)&address, sizeof(address)) < 0) {
        (void)syscall1(3, packet);
        return 0;
    }
    net_stage = 5;

    zero_bytes(request, sizeof(request));
    for (usize i = 0; i < 6; ++i)
        request[i] = 0xff;
    for (usize i = 0; i < 6; ++i)
        request[6 + i] = local_mac[i];
    request[12] = 0x08;
    request[13] = 0x06;
    request[14] = 0x00;
    request[15] = 0x01;
    request[16] = 0x08;
    request[17] = 0x00;
    request[18] = 6;
    request[19] = 4;
    request[20] = 0x00;
    request[21] = 0x01;
    for (usize i = 0; i < 6; ++i)
        request[22 + i] = local_mac[i];
    request[28] = 10;
    request[29] = 0;
    request[30] = 2;
    request[31] = 15;
    request[38] = expected_ip[0];
    request[39] = expected_ip[1];
    request[40] = expected_ip[2];
    request[41] = expected_ip[3];
    {
        long sent = syscall6(44, packet, (long)request, sizeof(request), 0,
                             (long)&address, sizeof(address));
        *tx_ok = sent == sizeof(request);
        if (!*tx_ok) {
            net_error = -sent;
            net_stage = 50;
            return 0;
        }
    }
    net_stage = 6;
    if (*tx_ok) {
        long length = syscall6(45, packet, (long)reply, sizeof(reply), 0, 0, 0);
        *rx_ok = length >= 42 && reply[12] == 0x08 && reply[13] == 0x06
                 && reply[20] == 0 && reply[21] == 2
                 && reply[28] == expected_ip[0]
                 && reply[29] == expected_ip[1]
                 && reply[30] == expected_ip[2]
                 && reply[31] == expected_ip[3];
        net_stage = 7;
    }
    (void)syscall1(3, packet);
    return *tx_ok && *rx_ok;
}

static int virtiofs_roundtrip(void) {
    static const char mountpoint[] = "/mnt";
    static const char source[] = "jasperfs";
    static const char filesystem[] = "virtiofs";
    static const char path[] = "/mnt/hello.txt";
    static const unsigned char initial[] = "Jasper virtio-fs";
    static const unsigned char suffix[] = " guest";
    unsigned char data[32];
    long fd;
    long open_error;
    int ok = 0;

    (void)syscall1(83, (long)mountpoint);
    fs_stage = 1;
    if (syscall5(165, (long)source, (long)mountpoint, (long)filesystem, 0, 0) != 0)
        return 0;
    fs_stage = 2;
    for (int attempt = 0; attempt < 32; ++attempt) {
        fd = syscall3(2, (long)path, 2, 0);
        if (fd >= 0)
            break;
        open_error = fd;
        (void)syscall1(24, 0);
    }
    if (fd < 0) {
        fs_stage = 20 + (int)(-open_error);
        return 0;
    }
    fs_stage = 3;
    if (syscall3(0, fd, (long)data, sizeof(initial) - 1)
        == (long)(sizeof(initial) - 1)) {
        ok = 1;
        for (usize i = 0; i < sizeof(initial) - 1; ++i) {
            if (data[i] != initial[i]) {
                ok = 0;
                break;
            }
        }
    }
    if (ok) {
        fs_write_result = syscall5(18, fd, (long)suffix, sizeof(suffix) - 1,
                                   sizeof(initial) - 1, 0);
        if (fs_write_result != (long)(sizeof(suffix) - 1))
            ok = 0;
        if (ok) {
            (void)syscall1(3, fd);
            fd = syscall3(2, (long)path, 0, 0);
            if (fd < 0)
                ok = 0;
        }
        if (ok) {
            fs_readback_result = syscall3(
                0, fd, (long)data, sizeof(initial) + sizeof(suffix) - 2);
            if (fs_readback_result
                != (long)(sizeof(initial) + sizeof(suffix) - 2))
                ok = 0;
            else {
                for (usize i = 0; i < sizeof(initial) - 1; ++i) {
                    if (data[i] != initial[i])
                        ok = 0;
                }
                for (usize i = 0; i < sizeof(suffix) - 1; ++i) {
                    if (data[sizeof(initial) - 1 + i] != suffix[i])
                        ok = 0;
                }
            }
        }
    }
    (void)syscall1(3, fd);
    fs_stage = 4;
    return ok;
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
    static const char net_marker[] =
        "<2>[JSR-HWV5-NET] device=net discovered=true link=true tx=true rx=true arp=true ok=true\n";
    static const char fs_marker[] =
        "<2>[JSR-HWV5-FS] device=fs discovered=true mount=true lookup=true read=true write=true ok=true\n";
    static const char net_start_marker[] =
        "<2>[JSR-LINUX-GUEST] stage=net-start\n";
    static const char pio_fail_marker[] =
        "<2>[JSR-LINUX-GUEST] stage=pio-failed\n";
    static const char fs_start_marker[] =
        "<2>[JSR-LINUX-GUEST] stage=fs-start\n";
    static const char done_marker[] =
        "<2>[JSR-LINUX-GUEST] done=true\n";
    static const char *const net_stage_markers[] = {
        "<2>[JSR-LINUX-GUEST] stage=net-stage-0\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-1\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-2\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-3\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-4\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-5\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-6\n",
        "<2>[JSR-LINUX-GUEST] stage=net-stage-7\n",
    };
    static const char *const fs_stage_markers[] = {
        "<2>[JSR-LINUX-GUEST] stage=fs-stage-0\n",
        "<2>[JSR-LINUX-GUEST] stage=fs-stage-1\n",
        "<2>[JSR-LINUX-GUEST] stage=fs-stage-2\n",
        "<2>[JSR-LINUX-GUEST] stage=fs-stage-3\n",
        "<2>[JSR-LINUX-GUEST] stage=fs-stage-4\n",
    };
    static const unsigned char block_expected[16] = "JASPER-BLOCK-001";
    unsigned char block_data[16];
    unsigned char random[8];
    int rng_ok;
    int console_ok;
    int block_ok;
    int pio_ok;
    int net_tx_ok = 0;
    int net_rx_ok = 0;
    int net_ok;
    int fs_ok;
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
        if (control == 0x4f49504aU) {
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
    if (!pio_ok) {
        fd = syscall3(2, (long)kmsg_path, 1, 0);
        if (fd >= 0) {
            write_all(fd, pio_fail_marker, sizeof(pio_fail_marker) - 1);
            (void)syscall1(3, fd);
        }
    }
    fd = syscall3(2, (long)kmsg_path, 1, 0);
    if (fd >= 0)
        write_all(fd, net_start_marker, sizeof(net_start_marker) - 1);
    if (fd >= 0)
        (void)syscall1(3, fd);
    net_ok = arp_roundtrip(&net_tx_ok, &net_rx_ok);
    fd = syscall3(2, (long)kmsg_path, 1, 0);
    if (fd >= 0 && net_stage < 8)
        write_cstr(fd, net_stage_markers[net_stage]);
    if (net_stage == 50 && fd >= 0) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] stage=net-send-error errno=");
        write_decimal(fd, (unsigned long)net_error);
        write_cstr(fd, "\n");
    }
    if (fd >= 0) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] net-flags=");
        write_decimal(fd, (unsigned long)net_flags);
        write_cstr(fd, " set-error=");
        write_decimal(fd, (unsigned long)-net_set_error);
        write_cstr(fd, "\n");
    }
    if (fd >= 0)
        write_all(fd, fs_start_marker, sizeof(fs_start_marker) - 1);
    if (fd >= 0)
        (void)syscall1(3, fd);
    fs_ok = virtiofs_roundtrip();
    fd = syscall3(2, (long)kmsg_path, 1, 0);
    if (fd >= 0 && fs_stage < 5)
        write_cstr(fd, fs_stage_markers[fs_stage]);
    if (fd >= 0 && fs_stage >= 20) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] stage=fs-open-error errno=");
        write_decimal(fd, (unsigned long)(fs_stage - 20));
        write_cstr(fd, "\n");
    }
    if (fd >= 0) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] fs-write-result=");
        if (fs_write_result < 0) {
            write_cstr(fd, "-");
            write_decimal(fd, (unsigned long)-fs_write_result);
        } else {
            write_decimal(fd, (unsigned long)fs_write_result);
        }
        write_cstr(fd, "\n");
    }
    if (fd >= 0) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] fs-readback-result=");
        write_decimal(fd, (unsigned long)fs_readback_result);
        write_cstr(fd, "\n");
    }
    if (fd >= 0) {
        write_cstr(fd, "<2>[JSR-LINUX-GUEST] fs-ok=");
        write_decimal(fd, (unsigned long)fs_ok);
        write_cstr(fd, "\n");
    }
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
        if (net_ok)
            write_all(fd, net_marker, sizeof(net_marker) - 1);
        if (fs_ok)
            write_all(fd, fs_marker, sizeof(fs_marker) - 1);
        if (console_ok)
            write_all(hvc, console_marker, sizeof(console_marker) - 1);
    }
    fd = syscall3(2, (long)kmsg_path, 1, 0);
    if (fd >= 0) {
        write_all(fd, done_marker, sizeof(done_marker) - 1);
        (void)syscall1(3, fd);
    }
    fd = syscall3(2, (long)console_path, 1, 0);
    if (fd >= 0) {
        write_all(fd, base_marker, sizeof(base_marker) - 1);
        if (pio_ok)
            write_all(fd, pio_marker, sizeof(pio_marker) - 1);
        else
            write_all(fd, pio_fail_marker, sizeof(pio_fail_marker) - 1);
        if (net_ok)
            write_all(fd, net_marker, sizeof(net_marker) - 1);
        if (fs_ok)
            write_all(fd, fs_marker, sizeof(fs_marker) - 1);
    }
    if (hvc >= 0) {
        if (pio_ok)
            write_all(hvc, pio_marker, sizeof(pio_marker) - 1);
        else
            write_all(hvc, pio_fail_marker, sizeof(pio_fail_marker) - 1);
        if (net_ok)
            write_all(hvc, net_marker, sizeof(net_marker) - 1);
        if (fs_ok)
            write_all(hvc, fs_marker, sizeof(fs_marker) - 1);
    }
    for (;;)
        (void)syscall1(34, 0);
}
