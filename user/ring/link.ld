/* user-ring 的链接脚本：固定装载到用户私有窗口内（0x1000_0040_0000 起）。
 * 代码、只读数据、可写数据各自按页对齐，装载器据段权限分别映射（代码可执行只读、数据可写不可执行）。
 * `.got` 并入可写数据段：否则它会单独成段并与只读数据同处一页，被装载器按页重叠拒绝。 */
ENTRY(_start)
SECTIONS
{
  . = 0x100000400000;
  .text   : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data   : { *(.data .data.*) *(.got .got.*) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
