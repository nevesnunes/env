# +

./asm.md
./evasion.md

```bash
# Any format
strings
# ELF format, validates shared libraries initialization
ldd -iv
# PE format
floss
```

https://zeltser.com/media/docs/malware-analysis-cheat-sheet.pdf

# methodology

- enumerate exports, imports, function use, syscalls, winapi, mutex, dll dependencies, strings
- monitoring FileRead and FileWrite calls
    - ~/share/forensics/APIMiner-v1.0.0/
    - [GitHub \- poona/APIMiner: API Logger for Windows Executables](https://github.com/poona/APIMiner/)
- monitor memory maps - snapshot at `entry()`, then check if executable section became writable and modified at later snapshot
- binary patching, code injection, fault inducing
- alternative to reverse debugging: vm snapshots

- [Tampering and Reverse Engineering - Mobile Security Testing Guide](https://mobile-security.gitbook.io/mobile-security-testing-guide/general-mobile-app-testing-guide/0x04c-tampering-and-reverse-engineering)

# vm

- https://www.microsoft.com/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/

# scripting dissassembly

- [Programming with Python language – Capstone – The Ultimate Disassembler](https://www.capstone-engine.org/lang_python.html)
- [find\_ioctls\.py · GitHub](https://gist.github.com/uf0o/011cedcae3f52102c69c7d8c28ae678c)

# side channels

- timing attacks - On password validation routine, when a char is correct, more instructions are executed
    - ~/code/snippets/pin/count_me_if_you_can.py
    - [write\-up for dont\_panic \- Eternal Stories](http://eternal.red/2017/dont_panic-writeup/)
- syscall counting - `strace | sort | uniq -c`

```bash
# instruction counting
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out \
    | awk '/Instrumentation results:/{print $3}'
qemu-x86_64 -d in_asm ~/a.out 2>&1 \
    | awk '/IN:/{i+=1} END{print i}'
gcc -O0 a.c && echo 'a' \
    | perf stat -e instructions:u ./a.out 2>&1 \
    | awk '/instructions.u/{print $1}'
# bruteforcing chars
for n in {32..127}; do
    c=$(awk '{ printf("%c", $0); }' <<< $n)
    printf '%s ' $c
    ~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out <(printf '%s' $c) | awk '/Instrumentation results:/{print $3}'
done 2>/dev/null | vim -
# [Counting instructions using Stalker · Issue \#94 · frida/frida\-python · GitHub](https://github.com/frida/frida-python/issues/94)
# https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# https://stackoverflow.com/questions/8841373/displaying-each-assembly-instruction-executed-in-gdb/46661931#46661931
# https://en.wikibooks.org/wiki/QEMU/Invocation

# coverage
~/opt/dynamorio/build/bin64/drrun -t drcov -dump_text -- ./a.out
diff -Nauw drcov.a.out.2575073.0000.proc.log drcov.a.out.2575098.0000.proc.log | vim -
# - diff alternative: `lighthouse` plugin
# - https://stackoverflow.com/questions/53218160/how-can-i-do-code-path-analysis-in-a-debugger
# - https://dynamorio.org/dynamorio_docs/page_drcov.html

# ||
# 1. grep xrefs from asm dump, take addresses
# 2. make gdb script with temporary breakpoint (`tbreak`) foreach address
# - [On why my tbreak tracing trick did not work \- gynvael\.coldwind//vx\.log](https://gynvael.coldwind.pl/?id=638)

# execution trace
# - https://github.com/teemu-l/execution-trace-viewer
```

# main function

On libc `entry`, take 1st argument to `__libc_start_main()`

# case studies

- https://github.com/quintuplecs/writeups/blob/master/FwordCTF/xo.md
    - strlen side-channel on flag xor - use dummy values as previous chars while guessing next char, since a right char generates a null byte, making strlen ignore next chars after the right char


