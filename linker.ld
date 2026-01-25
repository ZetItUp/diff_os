/*OUTPUT_FORMAT(elf64-x86-64)*/
OUTPUT_FORMAT(elf32-i386)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(0x5);  /* R | X */
    data PT_LOAD FLAGS(0x6);  /* R | W */
}

SECTIONS
{
    . = 1M;

    /* Multiboot header and entry point - must be first */
    .multiboot ALIGN(4K) : {
        *(.multiboot.data)
        *(.multiboot.text)
    } :text

    /* Text section (code) */
    .text ALIGN(4K) : {
        *(.text)
    } :text

    /* Read-only data */
    .rodata ALIGN(0x1000) : {
        *(.rodata)
        *(.rodata.*)
    } :text

    /* Datasection (initialized variables) */
    .data ALIGN(0x1000) : {
        *(.data)
    } :data

    .stack ALIGN(0x1000) : {
        __stack_bottom = .;
        . = . + 0x4000; /* 16 KB stack */
        __stack_top = .;
    } :data

    /* BSS-section  */
    .bss ALIGN(0x1000) : {
        __bss_start = .;
        *(.bss)
        __bss_end = .;
    } :data

    __heap_start = .;
    . = . + 8M;     /* 8MB Heap */
    __heap_end = .;
    /DISCARD/ : { *(.comment .note .eh_frame) }
}
