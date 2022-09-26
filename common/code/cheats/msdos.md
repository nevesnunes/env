# +

- [dosbox](./dosbox.md)

- Dissassembler with annotated interrupts: Sourcer

# Methodology

- trace back the code flow from the "program exit" points (`B4 4C CD 21 – MOV AH, 4Ch; INT 21h`)

# Interrupts

- input
    - [read key press](http://www.ctyme.com/intr/int-09.htm): when IRQ1 is fired, int 9 handler is called, read with `in al, 60h`
    - [check keyboard buffer](https://jbwyatt.com/253/emu/8086_bios_and_dos_interrupts.html#int16h_01h): `int 16h, ah = 01h`; **output**: al = char read
- teletype
    - [read char at cursor position](https://jbwyatt.com/253/emu/8086_bios_and_dos_interrupts.html#int10h_08h): `int 10h, ah 08h`; **input**: bh = page number; **output**: ah = attribute, al = char
    - [write char](https://jbwyatt.com/253/emu/8086_bios_and_dos_interrupts.html#int10h_0Eh): `int 10h, ah = 0Eh`; **input**: al = char
- filesystem
    - [open file](http://spike.scu.edu.au/~barry/interrupts.html#ah3d): `int 21h, ah = 3Dh`; **input**: al = mode, ds:dx = asciz filename; **output**: ax = file handle
- [VGA](https://wiki.osdev.org/VGA_Hardware)
    - [disassembly \- How is the I/O address space on the PC arranged? \- Reverse Engineering Stack Exchange](https://reverseengineering.stackexchange.com/questions/20333/how-is-the-i-o-address-space-on-the-pc-arranged)
    - ["EGA/VGA Bitplanes" by JAN DOGGEN](https://swag.outpostbbs.net/EGAVGA/0079.PAS.html)
    - ["Bitplanes in Mode 12h" by ARNE DE\.BRUIJN](http://www.retroarchive.org/swag/EGAVGA/0222.PAS.html)

- [Ralf Brown's Interrupt List \- HTML Version](https://www.ctyme.com/rbrown.htm)
- [basic 8086 and dos interrupts](https://jbwyatt.com/253/emu/8086_bios_and_dos_interrupts.html)
- [DOS INT 21h](http://spike.scu.edu.au/~barry/interrupts.html)

# Exporting data

- virtual printer

# Watcom

- [GitHub \- fonic/wcdctool: Watcom Decompilation Tool \(wcdctool\)](https://github.com/fonic/wcdctool)
    - https://github.com/open-watcom/open-watcom-v2/blob/master/bld/lib_misc/c/demangle.c
