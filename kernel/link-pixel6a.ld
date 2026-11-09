/*
 * Pixel 6a early-boot probe layout.
 *
 * ABL loads a v4 boot image kernel at 0x10000000 on bluejay. Keep the image
 * 2 MiB aligned and below 0x11000000, where vendor_boot places its ramdisk.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x10000000;
    __image_start = .;
    __kernel_start = .;

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

__image_size = __image_end - __image_start;

ASSERT(__kernel_end - __kernel_start <= 32 * 1024 * 1024, "kernel image larger than the early identity map")
ASSERT(__kernel_start % (2 * 1024 * 1024) == 0, "kernel must start on a 2 MiB boundary")
ASSERT(__kernel_end <= 0x11000000, "kernel overlaps Pixel vendor ramdisk address")
