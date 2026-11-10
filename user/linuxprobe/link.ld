ENTRY(_start)
SECTIONS
{
  . = JSR_LINUX_IMAGE_BASE;
  .text : {
    *(.text._start)
    *(.text .text.*)
  }
  . = ALIGN(4096);
  .rodata : {
    *(.rodata .rodata.*)
  }
  . = ALIGN(4096);
  .data : {
    *(.data .data.*)
    *(.got .got.*)
    *(.bss .bss.*)
    *(COMMON)
  }
  /DISCARD/ : {
    *(.eh_frame*)
    *(.comment)
    *(.note*)
  }
}
