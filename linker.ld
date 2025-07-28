/*OUTPUT_FORMAT(elf64-x86-64)*/
OUTPUT_FORMAT(elf32-i386)
ENTRY(_start)

SECTIONS
{
    
    . = 0x100000;

    /* Textsekction (code) */
    .text ALIGN(0x1000) : {
        *(.text.start)
        *(.text)
    }

    /* Read-only data */
    .rodata ALIGN(0x1000) : {
        *(.rodata)
        *(.rodata.*)
    }

    /* Datasection (initialized variables) */
    .data ALIGN(0x1000) : {
        *(.data)
    }

    .stack ALIGN(0x1000) : {
        __stack_bottom = .;
        . = . + 0x4000; /* 16 KB stack, väx nedåt */
        __stack_top = .;
    }

    /* BSS-section (zero-initialized variables) */
    .bss ALIGN(0x1000) : {
        __bss_start = .;
        *(.bss)
        __bss_end = .;
    }

    __heap_start = .;
    . = . + 1M;     /* 1MB Heap */
    __heap_end = .;
    /DISCARD/ : { *(.comment .note .eh_frame) }
}
