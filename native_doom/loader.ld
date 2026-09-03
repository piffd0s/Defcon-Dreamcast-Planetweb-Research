ENTRY(loader)
MEMORY { ram (rwx) : ORIGIN = 0x8C29AE00, LENGTH = 0x1000 }
SECTIONS { .text : { *(.text.start) *(.text*) *(.rodata*) *(.data*) } > ram }
