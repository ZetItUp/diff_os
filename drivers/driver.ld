SECTIONS
{
    . = 0x1000;

    .text   : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data   : { *(.data*) }
    .bss    : { *(.bss*) }

    /* Se till att symbol-/strängtabellerna INTE garbage-collectas */
    .ddf_symtab : { KEEP(*(.ddf_symtab)) }
    .ddf_strtab : { KEEP(*(.ddf_strtab)) }

    /* Behåll riktiga reloc-sektioner (krävs för --emit-relocs + patchern) */
    .rel.text     : { KEEP(*(.rel.text*)) }
    .rel.rodata   : { KEEP(*(.rel.rodata*)) }
    .rel.data     : { KEEP(*(.rel.data*)) }
    .rel.bss      : { KEEP(*(.rel.bss*)) }

    .rela.text    : { KEEP(*(.rela.text*)) }
    .rela.rodata  : { KEEP(*(.rela.rodata*)) }
    .rela.data    : { KEEP(*(.rela.data*)) }
    .rela.bss     : { KEEP(*(.rela.bss*)) }

    /* Din metadata (IRQ mm.) */
    .ddf_meta : { KEEP(*(.ddf_meta)) }
}

