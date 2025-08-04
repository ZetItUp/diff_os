ENTRY(_start)

SECTIONS
{
    /* Tvinga fram headern absolut vid adress 0 */
    . = 0x0000;
    .ddf_header : {
        KEEP(*(.ddf_header));
    }

    /* Resten av sektionerna */
    .text : { *(.text*) }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }
    .bss : { *(.bss*) }

    /* DDF symboltabeller */
    .ddf_symtab : {
        __ddf_symtab_start = .;
        KEEP(*(.ddf_symtab));
        __ddf_symtab_end = .;
    }
    
    .ddf_strtab : {
        KEEP(*(.ddf_strtab));
    }

    /* Beräkna offset för symboltabell */
    _ddf_symbol_table_offset = __ddf_symtab_start - .;
    _ddf_symbol_table_count = (__ddf_symtab_end - __ddf_symtab_start) / 12;
}
