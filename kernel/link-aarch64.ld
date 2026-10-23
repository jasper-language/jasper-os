/*
 * AArch64 内核链接脚本：没有引导器，固件或仿真器按 ELF 程序头把内核装到物理地址并跳到 `_start`，
 * MMU 打开后内核仍在同一地址运行（恒等映射）。
 * AArch64 kernel linker script: loaded at its physical address and kept identity-mapped.
 *
 * 布局：RAM 起点（QEMU virt 为 0x4000_0000）留出 2 MiB 给固件放设备树，内核从 +2 MiB 开始。
 * 各段 4 KiB 对齐，以便早期页表按段设置权限（代码只读可执行、只读数据不可执行、数据与 BSS 可写不可执行）。
 */
ENTRY(_start)

SECTIONS
{
    . = 0x40200000;
    __image_start = .;
    __kernel_start = .;

    /* arm64 Linux Image 头（64 字节）：code0 跳转到 _start，后面是 text_offset /
       image_size / flags / magic 等字段。QEMU -kernel 与真实引导器先读它，内核启动后再
       用同一份字节做一次自校验（PDA-1）。 */
    .image_header : {
        KEEP(*(.image_header))
    }

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    .rodata : {
        *(.rodata .rodata.*)
        *(.got .got.*)
    }
    . = ALIGN(4096);
    __rodata_end = .;

    .data : {
        *(.data .data.*)
    }

    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(4096);
    __kernel_end = .;
    __image_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }
}

/* `Image` 头里的 image_size（供汇编数据段直接引用，避免在汇编里做符号相减）。 */
__image_size = __image_end - __image_start;

/* 早期页表只为内核映像准备了 32 MiB 的 4 KiB 页表（见 arch/aarch64/mmu.rs 的 IMAGE_L3_TABLES）。 */
ASSERT(__kernel_end - __kernel_start <= 32 * 1024 * 1024, "kernel image larger than the early identity map")
ASSERT(__kernel_start % (2 * 1024 * 1024) == 0, "kernel must start on a 2 MiB boundary")
