OUTPUT_FORMAT(elf64-x86-64)

MEMORY
{
    rom (rx)  : ORIGIN = 0x400000, LENGTH = 0x100000
}

SECTIONS
{
    .text 0x401000 : { *(.text) } > rom

    /DISCARD/ : { *(.comment) *(.eh_frame*) *(.gnu*) *(.note*) }
}
