/*
 * LoongArch64 内核链接脚本。QEMU `virt` 的 `-kernel` 直接按 ELF 程序头装载
 * 到 0x0020_0000；低地址恒等映射由 arch/loongarch64/mmu.rs 在开启分页前建立。
 */
ENTRY(_start)

SECTIONS
{
    . = 0x00200000;
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

ASSERT(__kernel_end - __kernel_start <= 32 * 1024 * 1024, "kernel image larger than the early identity map")
ASSERT(__kernel_start % 4096 == 0, "kernel start must be page aligned")
