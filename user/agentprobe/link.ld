ENTRY(_start)
SECTIONS
{
  . = JSR_IMAGE_BASE;
  .note.jasper.abi : {
    LONG(8); LONG(8); LONG(1);
    LONG(0x5053414a); LONG(0x00005245);
    SHORT(JSR_ABI_MAJOR); SHORT(JSR_ABI_MINOR); SHORT(JSR_ABI_PATCH); SHORT(0);
  }
  . = ALIGN(4096);
  .text : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.got .got.*) *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
