ENTRY(_start)
MEMORY { ram (rwx) : ORIGIN = 0x8CC00000, LENGTH = 0x00280000 }
SECTIONS {
  .text : { *(.text.start) *(.text*) *(.rodata*) } > ram
  .data : { *(.data*) } > ram
  __bss_start = .;
  .bss  : { *(.bss*) *(COMMON) } > ram
  . = ALIGN(8);
  _end = .; __end = .; PROVIDE(end = .);
}
