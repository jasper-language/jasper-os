ENTRY(_start)
SECTIONS
{
  . = JSR_IMAGE_BASE;
  .note.jasper.abi : {
    LONG(8); LONG(8); LONG(1); LONG(0x5053414a); LONG(0x00005245);
    SHORT(JSR_ABI_MAJOR); SHORT(JSR_ABI_MINOR); SHORT(JSR_ABI_PATCH); SHORT(0);
  }
  .note.jasper.caps : {
    LONG(8); LONG(20); LONG(2); LONG(0x5053414a); LONG(0x00005245);
    SHORT(1); SHORT(0); SHORT(1); SHORT(0);
    BYTE(107); BYTE(101); BYTE(114); BYTE(110); BYTE(101); BYTE(108); BYTE(46);
    BYTE(99); BYTE(111); BYTE(114); BYTE(101); BYTE(0);
  }
  . = ALIGN(4096);
  .text : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data : { *(.data .data.*) *(.got .got.*) }
  .bss : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
