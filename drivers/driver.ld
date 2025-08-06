SECTIONS
{
    . = 0x1000;
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }
    .ddf_symtab : { *(.ddf_symtab) }
    .ddf_strtab : { *(.ddf_strtab) }
    .ddf_reloc : { *(.rel*) *(.rela*) }
    .ddf_meta : { *(.ddf_meta) }
}

