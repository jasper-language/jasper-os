/* user-rtdemo 的链接脚本：固定装载到用户私有窗口内（窗口起点 + 4 MiB；地址按指令集由构建脚本以 JSR_IMAGE_BASE 给出）。
 * 代码、只读数据、可写数据各自按页对齐，装载器据段权限分别映射（代码可执行只读、数据可写不可执行）。
 * `.got` 与 `.bss` 并入可写数据段：否则它们会单独成段并与相邻段同处一页，被装载器按页重叠拒绝
 * （`.bss` 因此以零字节存于文件中，代价是镜像略大）。 */
ENTRY(_start)
SECTIONS
{
  . = JSR_IMAGE_BASE;
  .text   : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data   : { *(.data .data.*) *(.got .got.*) *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
