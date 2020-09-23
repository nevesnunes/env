# +

- https://github.com/michalmalik/linux-re-101
    - https://syscalls.w3challs.com/
    - https://man7.org/linux/man-pages/man2/syscall.2.html
        - register conventions

- https://gcc.godbolt.org/
- https://onlinedisassembler.com/
- https://www.felixcloutier.com/x86/index.html
    - https://software.intel.com/en-us/articles/intel-sdm

# executable and linkable format (ELF)

- executable
    - contains: 1 or more segments
- segment
    - describes: execution view (loadable)
    - contains: 0 or more sections
- section
    - describes: linking view (instructions, data, symbols...)

https://web.archive.org/web/20171129031316/http://nairobi-embedded.org/040_elf_sec_seg_vma_mappings.html

# section headers

- `.text`: executable code; RX (=AX) segment; only loaded once, as contents will not change
    - CONTENTS, ALLOC, LOAD, READONLY, CODE
    - [finding address range](https://stackoverflow.com/questions/7370407/get-the-start-and-end-address-of-text-section-in-an-executable/7373301#7373301)
- `.data`: initialised data; RW (=WA) segment
- `.rodata`: initialised read-only data; R (=A) segment
- `.bss`: uninitialized data; RW segment
- `.plt`: PLT (Procedure Linkage Table) (IAT equivalent)
- `.got`: GOT entries dedicated to dynamically linked global variables
- `.got.plt`: GOT entries dedicated to dynamically linked functions
- `.symtab`: global symbol table
- `.dynamic`: Holds all needed information for dynamic linking
- `.dynsym`: symbol tables dedicated to dynamically linked symbols
- `.strtab`: string table of `.symtab` section
- `.dynstr`: string table of `.dynsym` section
- `.interp`: RTLD embedded string
- `.rel.dyn`: global variable relocation table
- `.rel.plt`: function relocation table

```bash
# sections + binary position
objdump -h
readelf --sections

# dump a section
objcopy --dump-section .text=output.bin input.o
```

# call convention (e.g. registers for arguments, return values)

https://man7.org/linux/man-pages/man2/syscall.2.html

# stack

- frame
    - contains: ebp; local vars; args; return address = eip saved by `call`

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

```asm
; function init ~= `enter` instruction
push rbp
mov rbp,rsp
push rbx

; stack space for locals
sub rsp,0x18

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

https://stackoverflow.com/questions/5959890/enter-vs-push-ebp-mov-ebp-esp-sub-esp-imm-and-leave-vs-mov-esp-ebp

- `ah`, - PRESERVES 0xffff00ff bits of `eax`, equivalent for `rax`
- `al`, `ax` - PRESERVES {8,16} high bits of `eax`, equivalent for `rax`
- `eax` - ZEROES 32 high bits of `rax`

https://stackoverflow.com/questions/25455447/x86-64-registers-rax-eax-ax-al-overwriting-full-register-contents/25456097

# assembling

```bash
gcc -no-pie -nostdlib foo.s -o foo
# || 32 bits
gcc -m32 -no-pie -nostdlib foo.s -o foo

# || Using Intel syntax
nasm -f elf -o foo.o foo.asm
ld -m elf_i386 -o foo foo.o

# || Using AT&T syntax
as -o foo.o foo.asm
ld -o foo foo.o
```

http://asm.sourceforge.net/intro/hello.html
https://cs.lmu.edu/~ray/notes/gasexamples/
https://stackoverflow.com/questions/36861903/assembling-32-bit-binaries-on-a-64-bit-system-gnu-toolchain

https://stackoverflow.com/questions/46756320/change-a-call-address-in-memory

# dissassembling

```bash
objdump -d _.so | grep func
nm -A _so | grep func

c++filt -n _ZdlPvm
readelf -Ws _.so
objdump -TC _.so
nm -gC _.so

# From raw data
# Reference: https://www.synacktiv.com/posts/challenges/sharkyctf-ezdump-writeups-linux-forensics-introduction.html
objdump -b binary -m i386:x64-32:intel -D shellcode.bin
```

# ARM

```bash
sudo apt install \
    qemu-system-arm \
    qemu-user
qemu-arm -L /usr/arm-linux-gnueabihf/ crackme
```

https://padraignix.github.io/reverse-engineering/2020/05/18/nsec2020-crackme/

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

# dynamic linking

https://in4k.github.io/wiki/lsc-wiki-rtld

# position independent executable (PIE)

https://stackoverflow.com/questions/2463150/what-is-the-fpie-option-for-position-independent-executables-in-gcc-and-ld
https://access.redhat.com/blogs/766093/posts/1975793
