/* user-hello 的链接脚本：固定装载到用户私有窗口内（窗口起点 + 4 MiB；地址按指令集由构建脚本以 JSR_IMAGE_BASE 给出）。
 * 代码、只读数据、可写数据各自按页对齐，装载器据段权限分别映射（代码可执行只读、数据可写不可执行）。 */
ENTRY(_start)
SECTIONS
{
  . = JSR_IMAGE_BASE;
  /* 程序 ABI 章：28 字节 ELF 注释节，由构建脚本以 JSR_ABI_MAJOR/MINOR/PATCH 传入。
   * 装载器在映射任何页之前读取它；同主版本要求 min_minor <= 内核 minor，跨主版本直接拒绝。 */
  .note.jasper.abi : {
    LONG(8);                 /* namesz */
    LONG(8);                 /* descsz */
    LONG(1);                 /* type = 程序 ABI 要求 */
    LONG(0x5053414a);        /* "JASP"（小端字节序：J A S P） */
    LONG(0x00005245);        /* "ER\0\0" */
    SHORT(JSR_ABI_MAJOR);
    SHORT(JSR_ABI_MINOR);
    SHORT(JSR_ABI_PATCH);
    SHORT(0);                /* flags = 0 */
  }
  /* ABI 1.1 required capability: this real Rust program needs kernel.core.
   * 版本 1 描述头 + NUL 结尾能力名；缺省该节表示旧 1.0 程序能力集为空。 */
  .note.jasper.caps : {
    LONG(8);                 /* namesz */
    LONG(20);                /* descsz */
    LONG(2);                 /* type = required capabilities */
    LONG(0x5053414a);        /* "JASP" */
    LONG(0x00005245);        /* "ER\0\0" */
    SHORT(1);                /* version */
    SHORT(0);                /* flags */
    SHORT(1);                /* count */
    SHORT(0);                /* reserved */
    BYTE(107); BYTE(101); BYTE(114); BYTE(110); BYTE(101); BYTE(108); BYTE(46);
    BYTE(99); BYTE(111); BYTE(114); BYTE(101); BYTE(0);
  }
  /* 章独占一页：与 .text 分属不同 PT_LOAD，避免页粒度重叠（装载器按页拒绝重叠段）。 */
  . = ALIGN(4096);
  .text   : { *(.text._start) *(.text .text.*) }
  . = ALIGN(4096);
  .rodata : { *(.rodata .rodata.*) }
  . = ALIGN(4096);
  .data   : { *(.data .data.*) }
  .bss    : { *(.bss .bss.*) *(COMMON) }
  /DISCARD/ : { *(.eh_frame*) *(.comment) *(.note*) }
}
