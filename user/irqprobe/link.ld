/* user-irqprobe 的链接脚本：固定装载到用户私有窗口内（窗口起点 + 4 MiB；地址按指令集由构建脚本以 JSR_IMAGE_BASE 给出）。
 * 代码、只读数据、可写数据各自按页对齐，装载器据段权限分别映射（代码可执行只读、数据可写不可执行）。 */
ENTRY(_start)
SECTIONS
{
  . = JSR_IMAGE_BASE;
  .text   : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  /* .got 是静态链接产生的重定位表；默认会被放进独立的 RELRO 段并落在只读段所在页内，
   * 与按页粒度校验的装载器冲突（system.elf.error.overlap）。这里并入可写数据段，保持页区间互不重叠。 */
  .data   : { *(.data .data.*) *(.got .got.*) *(.data.rel.ro .data.rel.ro.*) }
  . = ALIGN(4096);
  .bss    : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
