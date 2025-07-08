OUTPUT_FORMAT(elf64-x86-64)
ENTRY(kmain)

SECTIONS
{
    /* Place kernel at 1MB */
    . = 0x100000;

    /* Textsekction (code) */
    .text : {
        *(.text)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata)
    }

    /* Datasection (initialized variables) */
    .data : {
        *(.data)
    }

    .stack (NOLOAD) : {
        stack_start = .;
        . = . + 0x4000; /* 16 KB stack */
        stack_end = .;
    }

    /* BSS-section (zero-initialized variables) */
    .bss : {
        __bss_start = .;
        *(.bss)
        *(COMMON)
        __bss_end = .;
    }

}
