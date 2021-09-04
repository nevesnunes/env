# +

- https://syscalls.w3challs.com/
    - http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
    - https://filippo.io/linux-syscall-table/
    - ~/code/src/systems/execute-syscall
- https://man7.org/linux/man-pages/man2/syscall.2.html
    - register conventions
        - x64: rdi rsi rdx r10 r8 r9
- [Linker and Libraries Guide](https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/index.html)

- https://gcc.godbolt.org/
- https://onlinedisassembler.com/
- https://www.felixcloutier.com/x86/index.html
    - https://software.intel.com/en-us/articles/intel-sdm
- http://unixwiz.net/techtips/x86-jumps.html
- https://www.sandpile.org/

- [Notes on x86\-64 Assembly and Machine Code · GitHub](https://gist.github.com/mikesmullin/6259449)
- [Single Byte or Small x86 Opcodes \| Dru Nelson](http://xxeo.com/single-byte-or-small-x86-opcodes)
- [GitHub \- michalmalik/linux\-re\-101: A collection of resources for linux reverse engineering](https://github.com/michalmalik/linux-re-101)
- [NASM Tutorial](https://cs.lmu.edu/~ray/notes/nasmtutorial/)

```bash
# Assembler source listing, includes symbols
gcc -S -masm=intel

# Exploration
# Preconditions: `binutils` for arch
python3 -c '
from pwn import *
for ctx in [["arm", 32], ["aarch64", 64]]:
    context.arch, context.bits = ctx
    print(ctx)
    sh = shellcraft.sh()
    print(sh)
    print(hexdump(asm(sh)))
'
```

- https://github.com/unicorn-engine/unicorn/blob/master/bindings/python/sample_x86.py
- [ARM Assembly, Emulation, Disassembly using Keystone, Unicorn, and Capstone · GitHub](https://gist.github.com/cspensky/3a5153b29143e6be785a5e1a702bbd9e)

# mnemonics

```nasm
mov bx, 0
cmp bx, FF  ; 0 < -1 or 0 < 255 (sets CF AF SF)
jl foo      ; not taken, 0 > -1 (checks SF != OF)
jb foo      ; taken, 0 < 255 (checks CF = 1)
mov bx, FF
cmp bx, FF
je foo      ; taken, -1 + -(-1) = 0 (checks ZF = 1)
```

- [EFLAGS Individual Bit Flags](http://www.c-jump.com/CIS77/ASM/Instructions/I77_0070_eflags_bits.htm)
- [Jumps, flags, and the CMP instruction Article \|  Hellbound Hackers](https://www.hellboundhackers.org/articles/read-article.php?article_id=729)

> load effective address just takes the second operand was provided and gives the address of, similar to the & operator in c/cpp.
    > `lea r8d, [eax]` is the same as `mov r8d, eax` - usually `lea` is chosen since it can be dispatched on two ports (1/5 supporting fast LEA) and some things favor `lea` over alternatives for things like address incrementing (string ops).

# intrinsics

- [Intel&reg; Intrinsics Guide](https://software.intel.com/sites/landingpage/IntrinsicsGuide/#)
- [cheat sheet containing most x86 intrinsics, like SSE and AVX intrinsics](https://db.in.tum.de/~finis/x86-intrin-cheatsheet-v2.2.pdf?lang=en)

# portable executable (PE)

### main

```asm
CALL  _get_initial_narrow_environment
MOV   EDI,EAX
CALL  __p___argv
MOV   ESI,dword ptr [EAX]
CALL  __p___argc
PUSH  EDI
PUSH  ESI
PUSH  dword ptr [EAX]
CALL  FUN_00402100
```

- linux
    - `__libc_start_main()`
    - https://refspecs.linuxbase.org/LSB_5.0.0/LSB-Core-generic/LSB-Core-generic.html
    - [GNU Hurd / glibc / How libc startup in a process works](https://www.gnu.org/software/hurd/glibc/startup.html)
- windows
    - `_mainCRTStartup`
    - 3 pushes (arc, argv, envp) + call
    - https://docs.microsoft.com/en-us/cpp/build/reference/linking?view=msvc-160

# executable and linkable format (ELF)

- executable
    - contains: 1 or more segments
- segment
    - describes: execution view (loadable)
    - contains: 0 or more sections
- section
    - describes: linking view (instructions, data, symbols...)

- `man elf`
- ./files/ELF101.png
    - https://raw.githubusercontent.com/corkami/pics/master/binary/ELF101.png
- https://wiki.osdev.org/ELF#Tables
- https://fasterthanli.me/series/making-our-own-executable-packer/part-1
- https://web.archive.org/web/20171129031316/http://nairobi-embedded.org/040_elf_sec_seg_vma_mappings.html

# symbols

```bash
# Imports
objdump --dynamic-syms

# Externally visible / Exports
# ELF format
# Given: Symbol table '.dynsym'
nm --demangle --dynamic --defined-only --extern-only _
readelf -Ws _ | awk '{ if (!match("0000000000000000", $2)) print }'
# PE Format
winedump -j export foo.dll
mingw-objdump -p foo.dll
python3 -m pefile foo.exe
r2 -c 'iae' -qq foo.exe
env LD_PRELOAD=$HOME/share/forensics/pev/lib/libpe/libpe.so ~/share/forensics/pev/src/build/readpe foo.exe
# https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py
```

# section headers

```bash
# sections + binary position
objdump -h
readelf --sections
~/opt/pax-utils/dumpelf

# dump a section
objcopy --dump-section .text=output.bin input.o
```

|Sections|Lifecycle|
|--:|:--|
|`argc,argv,envp`||
|stack|grows to bottom (lower addresses)|
|heap|grows to top (higher addresses)|
|uninitialized data aka. `.bss`|zeroed by `exec`|
|initialized data aka. `.data`|read by `exec`|
|initialized read-only data aka. `.rodata`|read by `exec`|
|global offset table aka. `.got`|updated by `_dl_runtime_resolve`, replacing pointer to stub by resolved address, read in `.plt`|
|executable code aka. `.text`|read by `exec`|
|procedure linkage table aka. `.plt`||

- `.text`: executable code; RX (=AX) segment; only loaded once, as contents will not change
    - CONTENTS, ALLOC, LOAD, READONLY, CODE
    - [finding address range](https://stackoverflow.com/questions/7370407/get-the-start-and-end-address-of-text-section-in-an-executable/7373301#7373301)
- `.rela.text`: list of relocations against `.text` (e.g. extern variables)
- `.data`: initialised data; RW (=WA) segment
- `.rodata`: initialised read-only data; R (=A) segment
- `.bss`: uninitialized data (e.g. static or global variables); RW segment
- `.plt`: PLT (Procedure Linkage Table) (IAT equivalent)
- `.got`: GOT (Global Offset Table), used to access dynamically linked global variables, created during link time, may be populated during runtime
- `.got.plt`: used to access dynamically linked functions
    - lazy binding: value on 1st call = next instruction to load identifier and call linker; value on next calls = resolved address patched by linker in GOT
    ```
    5c0:   e8 0b ff ff ff         callq  4d0 <foo@plt>

    00000000000004d0 <foo@plt>:
    4d0:   ff 25 82 03 20 00      jmpq   *0x200382(%rip)        # 200858 <_GLOBAL_OFFSET_TABLE_+0x18>
    4d6:   68 00 00 00 00         pushq  $0x0
    4db:   e9 e0 ff ff ff         jmpq   4c0 <_init+0x18>

    Relocation section '.rela.plt' at offset 0x478 contains 2 entries:
    Offset          Info           Type           Sym. Value    Sym. Name + Addend
    000000200858  000400000007 R_X86_64_JUMP_SLO 0000000000000000 foo + 0
    ```
- `.symtab`: global symbol table
- `.dynamic`: Holds all needed information for dynamic linking
- `.dynsym`: symbol tables dedicated to dynamically linked symbols
- `.strtab`: string table of `.symtab` section
- `.dynstr`: string table of `.dynsym` section
- `.interp`: RTLD embedded string
- `.rel.dyn`: global variable relocation table, used for ASLR
- `.rel.plt`: function relocation table, used for ASLR

- [Technovelty \- PLT and GOT \- the key to code sharing and dynamic libraries ](https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html)
- [ELF Binaries and Relocation Entries \- shorne in japan](http://stffrdhrn.github.io/hardware/embedded/openrisc/2019/11/29/relocs.html)
- [c \- Why this piece of code can get environment variable address? \- Stack Overflow](https://stackoverflow.com/questions/40489161/why-this-piece-of-code-can-get-environment-variable-address)

### golf, strip

- https://www.sigflag.at/blog/2020/writeup-plaidctf2020-golfso/

# calling convention

- stdcall - callee cleans stack (i.e. `ret n`)
- cdecl - caller cleans stack (i.e. `add rsp` after call)
- fastcall - use registers for 1st 2 arguments (i.e. `sub rsp, n` + `ret n`)

- https://man7.org/linux/man-pages/man2/syscall.2.html
- https://en.wikipedia.org/wiki/X86_calling_conventions

### System V

- stack is 16 byte aligned
    - substract from rsp || push registers 

# stack

- frame
    - contains: $ebp; local vars (read w/ offset from $ebp, next address to alloc in $esp); args; return address = $eip saved by `call`
- segment flags: given section `.note.GNU-stack`, linker parses it and adds segment `PT_GNU_STACK`
    - if no section found, linker assumes executable bit is required
        - [Airs &\#8211; Ian Lance Taylor &raquo; Executable stack](https://www.airs.com/blog/archives/518)
    - if no segment added, behaviour is kernel dependent
        - Validation: `execstack` outputs `?`
        - [x86/elf: Split READ_IMPLIES_EXEC from executable PT_GNU_STACK \- kernel/git/torvalds/linux\.git \- Linux kernel source tree](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=122306117afe4ba202b5e57c61dfbeffc5c41387)

# self-modifying code

- X86 Emulator Plugin
    - Every time an instruction is fetched, the plugin tells IDA to turn that location into code
    - ~/Downloads/BH_Eagle_ida_pro.pdf

https://stackoverflow.com/questions/27581279/make-text-segment-writable-elf
https://stackoverflow.com/questions/54134394/segmentation-fault-with-a-variable-in-section-data
https://stackoverflow.com/questions/4812869/how-to-write-self-modifying-code-in-x86-assembly
https://0x00sec.org/t/polycrypt-experiments-on-self-modifying-programs/857
https://guyonbits.com/from-rodata-to-rwdata-introduction-to-memory-mapping-and-ld-scripts/
    ```gdb
    p (int)mprotect($rax - $rax%4096, 4096, 7)
    ```
without libc
    ```gdb
    # 10: __NR_mprotect
    set $rax = 10
    set $rdi = addr
    set $rsi = len
    set $rdx = 3
    jump syscall
    ```
    ? push/pop registers
    https://stackoverflow.com/questions/25740781/change-page-permission-using-gdb

# code cave

https://red0xff.github.io/writeups/volgactf_fhash/#6acb76aa304fcff925cebfc5ac2534de

# patterns

### stack

```asm
; function init/prologue ~= `enter` instruction
push rbp
mov rbp,rsp
push rbx

; stack space for locals
sub rsp,0x4
; ||
push param_1

; store argv[1]
mov rsi,qword [rsi + 0x8]

; [...]

; return value of next call
mov eax,0x0
; arguments of next call
mov rdi,0x1
call fun_0123

; mem ptr can be stored as extra local var
LEA RAX,[DAT_00100973]
MOV qword ptr [RBP + local_10],RAX
; ...added with var for addressing at index
MOV    EAX,dword ptr [RBP + local_18]
MOVSXD RDX,EAX
MOV    RAX,qword ptr [RBP + local_10]
ADD    RAX,RDX

; [...]

; release stack space
add rsp,0x18

; function exit ~= `leave` instruction
pop rbx
pop rsp
ret
```

- https://stackoverflow.com/questions/5959890/enter-vs-push-ebp-mov-ebp-esp-sub-esp-imm-and-leave-vs-mov-esp-ebp

|Frame|$rbp Offset|Value|Address|
|--:|--:|--:|:--|
| |+|`argc,argv,envp`|[...]|
|1|+|parameters      |[bgn]0x7fffffffffb0|
|1|+|`$rip`          |[bgn]0x7fffffffffa8|
|1|+|`$rbp`          |[end]0x7fffffffffa0|
|1|+|[alignment]     |[end]0x7fffffffff94|
|1|+|locals          |[end]0x7fffffffff30|
|2|+|parameters      |[...]|
|2|+|`$rip`          |[...]|
|2|0|`$rbp`          |[...]|
|2|-|[alignment]     |[...]|
|2|-|locals          |[...]|
|2|-|`$rsp`          |[...]|

- `$rbp` aka. frame pointer
- `$rip` aka. return address

### registers

- x86, x64
    - `ah`: PRESERVES 0xffff00ff bits of `eax`, equivalent for `rax`
    - `al`, `ax`: PRESERVES {8,16} high bits of `eax`, equivalent for `rax`
    - `eax`: ZEROES 32 high bits of `rax`
- arm, aarch64
    - `r0`: general, `x0`: 64 bits, `w0`: 32 bits
    - thumb mode
        > The opcode for "BX LR" is 0x70 0x47, which translates in ASCII to "pG". By running the strings command on a binary and grepping for this value, you can easily tell whether a chip is using Thumb code.
        - https://www.pentestpartners.com/security-blog/breaking-samsung-firmware-or-turning-your-s8-s9-s10-into-a-diy-proxmark/

- https://stackoverflow.com/questions/25455447/x86-64-registers-rax-eax-ax-al-overwriting-full-register-contents/25456097
- https://wiki.cdot.senecacollege.ca/wiki/AArch64_Register_and_Instruction_Quick_Start

# assembling

```bash
gcc -no-pie -nostdlib foo.s -o foo
# || 32 bits
gcc -m32 -no-pie -nostdlib foo.s -o foo

# || Using Intel syntax
nasm -f elf -o foo.o foo.asm
ld -m elf_i386 -o foo foo.o
# || 64 bits
nasm -f elf64 -o foo.o foo.asm
ld -m elf_x86_64 -o foo foo.o

# || Using AT&T syntax
as -o foo.o foo.asm
ld -o foo foo.o
```

- [The Yasm Modular Assembler Project](http://yasm.tortall.net/)

- http://asm.sourceforge.net/intro/hello.html
- https://cs.lmu.edu/~ray/notes/gasexamples/
- https://stackoverflow.com/questions/36861903/assembling-32-bit-binaries-on-a-64-bit-system-gnu-toolchain

- https://stackoverflow.com/questions/46756320/change-a-call-address-in-memory

# dissassembling

```bash
objdump -d _.so | grep func
nm -A _so | grep func

dumpbin /exports _.dll | find "func"
# || CFF Explorer

c++filt -n _ZdlPvm
readelf -Ws _.so
objdump -TC _.so
nm -gC _.so

# From raw data
# Reference: https://www.synacktiv.com/posts/challenges/sharkyctf-ezdump-writeups-linux-forensics-introduction.html
objdump -b binary -m i386:x64-32:intel -D shellcode.bin
```

# 16-bit

```bash
ida -m 0x100 -b 16 foo.com
```

# 32-bit vs. 64-bit

- pe format:
    - header: `50450000????`
        - 32: `014c`, 64: `8664`
    - `dumpbin /headers foo`

# cross-architecture

```bash
# multiarch
sudo apt install \
    binutils-aarch64-linux-gnu \
    binutils-mips-linux-gnu \
    binutils-powerpc-linux-gnu \
    binutils-arm-linux-gnueabi \
    libc6-arm64-cross \
    qemu-user \
    qemu-user-static

# arm
sudo apt install \
    qemu-system-arm \
qemu-arm -L /usr/arm-linux-gnueabihf/ crackme

# debug
qemu-aarch64 -singlestep -g 1234 -L /usr/aarch64-linux-gnu/ foo
gdb-multiarch -ex 'target remote localhost:1234'
```

- build objdump from binutils for target architecture
- https://github.com/OAlienO/CTF/tree/master/2018/HITCON-CTF/Baldis-RE-Basics
- https://padraignix.github.io/reverse-engineering/2020/05/18/nsec2020-crackme/

### compiling

```bash
sudo apt install \
    gcc-arm-linux-gnueabi \
    gcc-arm-linux-gnueabihf \
    binutils-arm-linux-gnueabi \
    libc6-armel-cross \
    libc6-dev-armel-cross
arm-linux-gnueabi-gcc ~/code/wip/hello.c -o hello_arm_static -static
```

https://www.acmesystems.it/arm9_toolchain

### attaching to debugger

```bash
qemu-arm -g 18080 _
gdb-multiarch _
# set arch mips
# set endian big
# target remote localhost:18080
```

https://padraignix.github.io/reverse-engineering/2020/05/18/nsec2020-crackme/

# boot disk, MBR

```bash
qemu-system-x86_64 -s -S -m 512 -fda winxp.img
```

https://github.com/VoidHack/write-ups/tree/master/Square%20CTF%202017/reverse/floppy

# toolchains

- [Toolchains\.net \- Toolchain resources](https://www.toolchains.net/)
- [ggx \- How To Retarget the GNU Toolchain in 21 Patches](http://atgreen.github.io/ggx/)
- [crosstool\-NG \- versatile \(cross\) toolchain generator](https://crosstool-ng.github.io/)
- [GitHub \- tpoechtrager/osxcross: Mac OS X cross toolchain for Linux, FreeBSD, OpenBSD and Android \(Termux\)](https://github.com/tpoechtrager/osxcross)

# dynamic linking

https://in4k.github.io/wiki/lsc-wiki-rtld

# position independent executable (PIE)

https://stackoverflow.com/questions/2463150/what-is-the-fpie-option-for-position-independent-executables-in-gcc-and-ld
https://access.redhat.com/blogs/766093/posts/1975793

# switching between 32-bit and 64-bit modes

- far return (`retf`)
    - next address pushed before call
    - `cs=0x23`: x86 mode
    - `cs=0x33`: x86-64 mode

- https://blukat29.github.io/2016/10/hitcon-quals-2016-mixerbox/
- [CTFtime\.org / Hack The Vote 2020 / x96](https://ctftime.org/task/13567)
- http://wiki.osdev.org/X86-64#Long_Mode

# endianess

```c
uint32_t read_le_int32(unsigned char *b) {
    return uint32_t(b[0]) |
            (uint32_t(b[1]) << 8) |
            (uint32_t(b[2]) << 16) |
            (uint32_t(b[3]) << 24);
}
```

# floating point precision

```gdb
# Given `addsd  xmm0, xmm0`, check result
info register xmm0
```

- [The Floating\-Point Guide \- What Every Programmer Should Know About Floating\-Point Arithmetic](https://floating-point-gui.de/)
- [What Every Computer Scientist Should Know About Floating\-Point Arithmetic](https://docs.oracle.com/cd/E19957-01/806-3568/ncg_goldberg.html)

# absolute indirect call

```nasm
mov rax, 0x7fffdeadbeef
call rax

; 3-byte max per ins, method 1
mov al, func_b3            ; EAX = ######b3
mov ah, func_b2            ; EAX = ####b2b3
bswap eax                  ; EAX = b3b2####
mov ah, func_b1            ; EAX = b3b2b1##
mov al, func_b0            ; EAX = b3b2b1b0
call eax

; 3-byte max per ins, method 2
mov ah, func_b3            ; EAX = ####b3##
mov al, func_b2            ; EAX = ####b3b2
shl eax, 16                ; EAX = b3b20000
mov ah, func_b1            ; EAX = b3b2b100
mov al, func_b0            ; EAX = b3b2b1b0
call eax
```

- https://stackoverflow.com/questions/19552158/call-an-absolute-pointer-in-x86-machine-code
- https://stackoverflow.com/questions/57261594/is-it-possible-to-call-a-relative-address-with-each-instruction-at-most-3-bytes

# address translation

- https://github.com/hasherezade/bearparser/wiki/bearcommander

### windows

- virtual address (VA) = original virtual address of object loaded into memory
- relative virtual address (RVA) = VA - ImageBase
    - e.g. 0x1000 = 0x401000 - 0x400000
- file offset of entry point = (.OptionalHeaders[EntryPointAddress] – .SectionHeaders[VirtualAddress[.text]]) + .SectionHeaders[PointerToRawData[.text]]

- [/BASE \(Base Address\) \| Microsoft Docs](https://docs.microsoft.com/en-us/cpp/build/reference/base-base-address?view=msvc-160)
- [Why is 0x00400000 the default base address for an executable? \| The Old New Thing](https://devblogs.microsoft.com/oldnewthing/20141003-00/?p=43923)

### linux

- ImageBase = ld script variable `__executable_start` = 0x400000
    - e.g. `ld -M /bin/ls`
    - https://reverseengineering.stackexchange.com/questions/16841/address-to-file-offset
- SectionHeaders == ProgramHeaders
- ! segment starts at next page-aligned virtual address due to mmap behaviour
    - https://stackoverflow.com/questions/42599558/elf-program-header-virtual-address-and-file-offset

# object-oriented code

- init
    1. `new()`
        ```
        PUSH 0xc ; size of object
        CALL ...
        ```
    2. if EAX not zero, then call constructor
- structs
    1. find calls where 1st argument is ptr to struct
    2. find 1st function initializing struct (i.e. constructor || setter)
    3. on 1st struct var, reset ptr type, create new struct type
        - unidentified members = char[k] "extra" member
    4. foreach call, fix type of ptr to struct
    - https://oalabs.openanalysis.net/2019/06/03/reverse-engineering-c-with-ida-pro-classes-constructors-and-structs/
- virtuals
    - object constructor stores field w/ ptr to class vftable, which contains addresses for vfuncs
        - polymorphism: overriden entries in vftable
        - multiple inheritance: multiple ptrs to vftables
    - rtti contains constructor names

- Ghidra-Cpp-Class-Analyzer
    - Analysis > All Open > Deselect All > Windows (or GCC) C++ Class Analyzer (prototype) > Decompiler timeout

- [Getting Started Reversing C\+\+ Objects with Ghidra \- YouTube](https://www.youtube.com/watch?v=ir2B1trR0fE)
- [Reversing Basic C\+\+ Objects with Ghidra: Inheritance and Polymorphism \(Part 2\) \- YouTube](https://www.youtube.com/watch?v=MiX4p2l_IE0)

# methodologies

- rom map
    - http://datacrystal.romhacking.net/wiki/EarthBound:ROM_map
- xrefs and symbol exports
    - https://tcrf.net/Proto:Sonic_the_Hedgehog_2_(Genesis)/Nick_Arcade_Prototype#Object_List.2FSource_Code
- split dissassemblies
    > The splitting program searches for pointers in the ROM where data is know to be stored (art, maps, etc.) and splits them out into seperate files (Ness’s art is in one file, Onett’s map is in it’s own file, etc.) for hacking ease. Also, an altered ASM source code is included, with tags that include this split data back in when building. This cuts down on the size of the source code file, as the normal file still contains the data for all these other resources. A comprehensive disassembly may even be done to include subroutine names to help understand which sub does what (like a sub would be called art_unc that uncompresses art, or battle_start when a battle begins).

# examples

### minimal elf

1. take `e_entry` @ 0x18
2. take `vaddr` @ 0x34 (3rd field of 1st program header)
3. disassemble from `file offset = *e_entry - *vaddr`

- e.g. code overlaps header
    - https://github.com/mathiasbynens/small/blob/master/elf.o
    ```bash
    dd if=elf.o of=elf.o.entry skip=$((0x19 + 1)) bs=1 count=$(($(wc -c < elf.o) - $((0x19 + 1))))
    objdump -b binary -m i386:x64-32:intel -D elf.o.entry
    # 0000000000000000 <.data>:
    #    0: cd 80   int 0x80
    ```

### arm, aarch64

- https://azeria-labs.com/writing-arm-assembly-part-1/
- https://thinkingeek.com/arm-assembler-raspberry-pi/
- https://opensecuritytraining.info/IntroARM.html
