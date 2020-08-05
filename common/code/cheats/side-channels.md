# instruction count

### pin

https://github.com/dqi/ctf_writeup/tree/master/2015/hackover/reversing/%20i-like-to-move-it
https://ctftime.org/writeup/8861
https://github.com/pres1er/writeups/blob/master/nullcon19/Dr_Owl/solve.py
    https://github.com/nullcon/hackim-2019/tree/master/re/dr-owl

### gdb

```
gdb program
start
record btrace pt
cont

record instruction-history /m # show instructions
record function-history # show functions executed
prev # step backwards in time
```

[Cheat sheet for Intel Processor Trace with Linux perf and gdb at Andi Kleen&\#039;s blog](http://halobates.de/blog/p/410)
https://stackoverflow.com/questions/54355631/how-do-i-determine-the-number-of-x86-machine-instructions-executed-in-a-c-progra

# memory access

```bash
~/opt/dynamorio/build/bin64/drrun -c ~/opt/dynamorio/build/api/bin/libmemtrace_simple.so -- ./a.out
```

https://fritshoogland.wordpress.com/2016/11/18/advanced-oracle-memory-profiling-using-pin-tool-pinatrace/
https://www.voidsecurity.in/2015/09/csaw-ctf-re500-wyvern.html
