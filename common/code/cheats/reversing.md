# +

./asm.md

```bash
# Any format
strings
# ELF format
ldd
# PE format
floss
```

- Malware Evasion
    - [Map \- Unprotect Project](https://search.unprotect.it/map)

# vm

- https://www.microsoft.com/security/blog/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/

# scripting dissassembly

- [Programming with Python language – Capstone – The Ultimate Disassembler](https://www.capstone-engine.org/lang_python.html)
- [find\_ioctls\.py · GitHub](https://gist.github.com/uf0o/011cedcae3f52102c69c7d8c28ae678c)

# side channels

- timing attacks - On password validation routine, when a char is correct, more instructions are executed
    - ~/code/snippets/pin/count_me_if_you_can.py
    - [write\-up for dont\_panic \- Eternal Stories](http://eternal.red/2017/dont_panic-writeup/)

```bash
# instruction counting
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libinscount.so -- ./a.out \
    | awk '/Instrumentation results:/{print $3}'
qemu-x86_64 -d in_asm ~/a.out 2>&1 \
    | awk '/IN:/{i+=1} END{print i}'
gcc -O0 a.c && echo 'a' \
    | perf stat -e instructions:u ./a.out 2>&1 \
    | awk '/instructions.u/{print $1}'
# [Counting instructions using Stalker · Issue \#94 · frida/frida\-python · GitHub](https://github.com/frida/frida-python/issues/94)
# https://stackoverflow.com/questions/22507169/how-to-run-record-instruction-history-and-function-call-history-in-gdb
# https://stackoverflow.com/questions/8841373/displaying-each-assembly-instruction-executed-in-gdb/46661931#46661931
# https://en.wikibooks.org/wiki/QEMU/Invocation

# coverage
~/opt/dynamorio/build/bin64/drrun -t drcov -dump_text -- ./a.out
diff -Nauw drcov.a.out.2575073.0000.proc.log drcov.a.out.2575098.0000.proc.log | vim -
# https://stackoverflow.com/questions/53218160/how-can-i-do-code-path-analysis-in-a-debugger
# https://dynamorio.org/dynamorio_docs/page_drcov.html
```

# case studies

- https://github.com/quintuplecs/writeups/blob/master/FwordCTF/xo.md
    - strlen side-channel on flag xor - use dummy values as previous chars while guessing next char, since a right char generates a null byte, making strlen ignore next chars after the right char


