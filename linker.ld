/*OUTPUT_FORMAT(elf64-x86-64)*/
OUTPUT_FORMAT(elf32-i386)
ENTRY(kmain)


SECTIONS
{
    
    . = 0x100000;

    /* Textsekction (code) */
    .text : {
        *kernel.o(.text)
        *isr_stub.o(.text)
        *(.text)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata)
        *(.rodata.*)
    }

    /* Datasection (initialized variables) */
    .data : {
        *(.data)
    }

    .stack : {
        __stack_bottom = .;
        . = . + 0x4000; /* 16 KB stack, väx nedåt */
        __stack_top = .;
    }

    /* BSS-section (zero-initialized variables) */
    .bss : {
        __bss_start = .;
        *(.bss)
        __bss_end = .;
    }
    /DISCARD/ : { *(.comment .note .eh_frame) }
}
