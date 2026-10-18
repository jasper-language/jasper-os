/*
 * RISC-V 64 位内核链接脚本：没有引导器，机器态固件按 ELF 程序头把内核装到物理地址，以监管态跳到 `_start`，
 * 启用地址转换后内核仍在同一地址运行（恒等映射）。
 * RISC-V 64-bit kernel linker script: loaded at its physical address and kept identity-mapped.
 *
 * 布局：RAM 起点（QEMU virt 为 0x8000_0000）的前 2 MiB 归机器态固件（OpenSBI），内核从 +2 MiB 开始。
 * 各段 4 KiB 对齐，以便早期页表按段设置权限（代码只读可执行、只读数据不可执行、数据与 BSS 可写不可执行）。
 */
ENTRY(_start)

SECTIONS
{
    . = 0x80200000;
    __kernel_start = .;

    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    . = ALIGN(4096);
    __text_end = .;

    .rodata : {
        *(.rodata .rodata.*)
        *(.srodata .srodata.*)
        *(.got .got.*)
    }
    . = ALIGN(4096);
    __rodata_end = .;

    .data : {
        *(.data .data.*)
        *(.sdata .sdata.*)
    }

    .bss (NOLOAD) : {
        . = ALIGN(16);
        __bss_start = .;
        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        . = ALIGN(16);
        __bss_end = .;
    }
    . = ALIGN(4096);
    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }
}

/* 早期页表只为内核映像准备了 16 张末级表（32 MiB）。 */
ASSERT(__kernel_end - __kernel_start <= 32 * 1024 * 1024, "kernel image larger than the early identity map")
ASSERT(__kernel_start % (2 * 1024 * 1024) == 0, "kernel must start on a 2 MiB boundary")
