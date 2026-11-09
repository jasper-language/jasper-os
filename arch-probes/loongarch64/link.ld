ENTRY(_start)

SECTIONS
{
    . = 0x00200000;
    __probe_start = .;

    .text : {
        KEEP(*(.text.entry))
        *(.text .text.*)
    }
    . = ALIGN(16);

    .rodata : {
        *(.rodata .rodata.*)
    }
    . = ALIGN(16);

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
    . = ALIGN(16);
    __probe_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }
}

