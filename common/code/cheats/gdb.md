# +

- hardware breakpoint - evades checks for int3
    - https://sourceware.org/gdb/onlinedocs/gdb/Set-Breaks.html
- https://stackoverflow.com/questions/5480868/how-to-call-assembly-in-gdb
- http://bl0rg.krunch.be/segfault-gdb-strace.html
- [How Does a C Debugger Work? \(2014\) | Hacker News](https://news.ycombinator.com/item?id=24814854)

- https://github.com/taskcluster/react-gdb

- PTRACE_PEEKUSER: access tracee process state
    - https://code.woboq.org/qt5/include/sys/user.h.html

```bash
# address space layout
cat /proc/789/maps

# disable ASLR
echo 0 > /proc/sys/kernel/randomize_va_space
# ||
setarch "$(uname -m)" -R /bin/zsh

# disable NX
execstack -s foo

# toggle core dumps
ulimit -c unlimited / ulimit -c 0
```

```gdb
# handle signals
handle SIGSEGV nostop nopass

# break on current instruction of running inferior
# <Ctrl-C>

# break on library function not yet loaded
set breakpoint pending on
b foo

info files
info f
info args
info stack

info all-registers
info registers eflags

info frame
frame n

info threads
thread n

bt full

printf "%p\n", __libc_start_main
printf "%x\n", (0x7ffff7e2afb0 + 0x043980)
disass 0x7ffff7e2afb0
x/i $pc
# 0x7fffff6681db <_pselect+91>: cmp rax,0xfffffffffffff000
x/-1i $pc
# 0x7fffff6681d9 <_pselect+89>: syscall

p/x $rbp - 0xc
$5 = 0x7fffffffd124
x/d $rbp - 0x0c
0x7fffffffd124: 2078
x/x $rbp - 0x0c
0x7fffffffd124: 0x0000081e
x/4wx $rsp
0x7fffffffd120: 0xffffd220      0x0000081e      0x55554973      0x00005555
x/10x $rsp
0x7fffffffd120: 0xffffd220      0x0000081e      0x55554973      0x00005555
0x7fffffffd130: 0x55554ee0      0x00005555      0xf7ddd042      0x00007fff
0x7fffffffd140: 0xffffd228      0x00007fff
# xref. return addresses
bt
0  0x0000555555554a7a in ?? ()
1  0x00007ffff7ddd042 in __libc_start_main (main=0x555555554bea, argc=1, argv=0x7fffffffd228, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffd218) at ../csu/libc-start.c:308
2  0x000055555555483a in ?? ()

# /!\ rbp is char**
# Modifies one char:
set *(char*)($rbp - 0x18) = 0x41424344
# Modifies all chars:
set *(char**)($rbp - 0x18) = 0x41424344

# /!\ A syntax error in expression, near `**)($rbp - 0x30) = 0x8'
p ($rbp - 0x30)
# $2 = (void *) 0x7ffff5815d00
set *0x7ffff5815d00 = 0x8

# Write value from address
set {int}0x123 = 0x456
# Write value from file
restore data.txt binary 0x123
# Write value with libc
call memcpy(0x123, "\x01\x02\x03\x04", 4)

# Allocate memory for value
set $malloc = (void*(*)(long long)) malloc 
set $mem = $malloc(sizeof(long)) 
p $mem 
# $1 = (void *) 0x5591420469b0 
p *(long*)$mem = (int*)func_that_returns_addr()
# ||
p *(long*)0x5591420469b0 = (int*)func_that_returns_addr()
watch **(long*)$mem

# errno
# - [Interface Definitions for libc - __errno_location](http://refspecs.linux-foundation.org/LSB_4.1.0/LSB-Core-generic/LSB-Core-generic/baselib---errno-location.html)
# - [What is errno really defined as](https://sourceware.org/legacy-ml/libc-help/2014-10/msg00022.html)
# - https://android.googlesource.com/platform/bionic/+/refs/heads/master/libc/include/errno.h#52
#     - `__errno()`
# - [!] thread-local, and address is only set after glibc init
watch *(int*)__errno_location()
# Take watchpoint number, e.g. 2
info watchpoints
condition 2 *(int*)__errno_location() == 3
# Alternatives:
# - https://github.com/iddoeldor/frida-snippets#one-time-watchpoint

# Setting errno in asm
# mov    dword ptr [rax], 2
# call   __errno_location@plt <__errno_location@plt>
```

# methodology

compile a dummy file with -g that has the types you need and then symbol-file it into gdb to get access to the types. This of course has caveats, you have to use the correct compiler and library versions, correct compiler target and ABI-changing flags, etc.

# saving / restoring register state

- https://sourceware.org/gdb/current/onlinedocs/gdb/Checkpoint_002fRestart.html
    - :( previous side-effects still applied

# scripting

```python
import gdb

def get_arg():
    v = int(re.findall("\t0x([0-9a-f]{8})", gdb.execute("x/1xw $rdi + 0x34", to_string=True))[0], 16)
    return v & 0xffff, v >> 16

gdb.execute("break *0x4009dc")
gdb.execute("r <<< $(echo 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')")
address = int(str(gdb.parse_and_eval("$eax")),16)
value = int(str(gdb.parse_and_eval("$eax")))
gdb.execute("set $dl = $al")
gdb.execute("set *(char**)($rbp - 0x18) = {}".format(candidate))

# loop for breakpoints that are hit more than once
while True:
    rip = int(str(gdb.parse_and_eval("$rip")), 16)
    if rip == 0x555555554000 + 0x97C:
        gdb.execute("set $rip = (0x555555554000 + 0x99A)")
        gdb.execute("c")
    elif rip == 0x555555554000 + 0xA52:
        break

# Debugging (ipdb doesn't work)
time.sleep(99999)
# Then send `C-c`, expect gdb prompt
```

- [CTFtime\.org / EKOPARTY CTF 2017 / WarmUp / Writeup](https://ctftime.org/writeup/7519)
- https://sourceware.org/gdb/onlinedocs/gdb/Inferiors-In-Python.html#Inferiors-In-Python
- https://ptr-yudai.hatenablog.com/entry/2020/02/09/140839

# dump memory

```bash
grep rw-p /proc/$1/maps \
    | sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
    | while read -r start stop; do \
        gdb --batch --pid $1 -ex \
            "dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
    done
```

https://serverfault.com/questions/173999/dump-a-linux-processs-memory-to-file/486304

Alternatives: `gcore -a $pid`

# shellcode

```c
char shellcode[] = "\xbb\x14\x00\x00\x00"
    "\xb8\x01\x00\x00\x00"
    "\xcd\x80";
```

```gdb
(gdb) print /x &shellcode
$1 = 0x804a010
(gdb) disas &shellcode
Dump of assembler code for function shellcode:
   0x0804a010 :	mov    $0x14,%ebx
   0x0804a015 :	mov    $0x1,%eax
   0x0804a01a :	int    $0x80
   0x0804a01c :	add    %al,(%eax)
```

https://hack3rlab.wordpress.com/gdb-disassemble-instructions-in-hex-format/

# Watchpoints

```gdb
# Break on register write
watch $rax

# Break on memory access
rwatch *0xfeedface

# == with specific type
rwatch *(int*)0xfeedface

# == for member of method
rwatch -location mTextFormatted

# Validation
show can-use-hw-watchpoints
```

# Countdown latch equivalent

```c
int debug_wait = 1;
while (debug_wait);
```

After all processes reached `while` loop:

```gdb
set {int}debug_wait = 0
```

http://heather.cs.ucdavis.edu/~matloff/pardebug.html

# Catch syscall

```gdb
# do nothing on break
catch syscall
commands
c
end
```

```
(gdb) catch syscall access
Catchpoint 1 (syscall 'access' [21])
(gdb) condition 1 $_streq((char *)$rdi, "/etc/ld.so.preload")
(gdb) ru
Starting program: /bin/ls 

Catchpoint 1 (call to syscall access), 0x00007ffff7df3537 in access ()
    at ../sysdeps/unix/syscall-template.S:81
81      ../sysdeps/unix/syscall-template.S: No such file or directory.
(gdb) p (char *)$rdi
$1 = 0x7ffff7df9420 <preload_file> "/etc/ld.so.preload"
```

- https://stackoverflow.com/questions/6517423/how-to-do-an-specific-action-when-a-certain-breakpoint-is-hit-in-gdb
- https://sourceware.org/gdb/onlinedocs/gdb/Set-Catchpoints.html
- https://sourceware.org/gdb/onlinedocs/gdb/Convenience-Funs.html

# Follow child processes

```gdb
# [!] may want to skip system()
set follow-fork-mode child
catch exec
# switch sides of fork
set detach-on-fork off
info inferiors
inferior 1
```

# Address in binary

```gdb
bt
#0 0x00005555555546a8 in fillBuffer ()
#1 0x00005555555546e1 in main ()

info proc mappings
# Mapped address spaces:
# Start Addr End Addr Size Offset objfile
# 0x555555554000 0x555555555000 0x1000 0x0 /vagrant/shouldve_gone_for_the_head
# [output truncated]
# =>
# 0x00005555555546a8 - 0x555555554000 + 0x0 = 0x6a8
```

- empty pathname
    > If the pathname field is blank, this is an anonymous mapping as obtained via mmap(2).  There is no easy way to coordinate this back to a process's source, short of running it through gdb(1), strace(1), or similar.
    - https://man7.org/linux/man-pages/man5/proc.5.html

- https://blog.trailofbits.com/2019/08/29/reverse-taint-analysis-using-binary-ninja/

# Functions

```
define callstack
     set $Cnt = $arg0

     while($Cnt)
        commands $Cnt
        silent
        bt
        c
        end
        set $Cnt = $Cnt - 1
     end
end

set pagination off
set logging file gdb.txt
set logging on

br fun_convert
commands
    bt
    print "Sample print command 1 \n"
    continue
end

continue

gdb -x FILE
gdb -ex run --args prog arg

checkpoint
i checkpoint
restart checkpoint-id
```

# compiling

```bash
wget https://ftp.gnu.org/gnu/gdb/gdb-8.1.tar.gz
tar -xvf gdb-8.1.tar.gz
cd gdb-8.1
mkdir build
cd build
../configure --prefix=/usr --disable-nls --disable-werror --with-system-readline --with-python=/usr/bin/python3.6 --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all
make -j7
sudo make install
```

https://github.com/pwndbg/pwndbg/issues/577#issuecomment-445590185

# plugins

./peda.md

```gdb
# gdb-dashboard
dashboard -output $(tty)
```

# case studies

### Stack frame manipulation

[GitHub \- c3r34lk1ll3r/gdb\_2\_root: This python script adds some usefull command to stripped vmlinux image](https://github.com/c3r34lk1ll3r/gdb_2_root)

### Dump bash command history of an active shell user

```bash
APID=1234
gdb \
    -batch \
    --eval "attach $APID" \
    --eval "call write_history(\"/tmp/bash_history-$APID.txt\")" \
    --eval 'detach' \
    --eval 'q'
```

- https://www.commandlinefu.com/commands/view/11427/dump-bash-command-history-of-an-active-shell-user

Alternative:

1. get function virtual address

```gdb
info function write_history
# Non-debugging symbols:
# 0x000056206763e420  write_history
```
    - || `objdump --dynamic-syms /usr/bin/bash | grep write_history`
    - || `strace` - trace process with stack traces, take all addresses where file open/write is called

2. get source code, find `write_history` function signature

```bash
grep -rin write_history
# ./lib/readline/history.h:207:extern int write_history PARAMS((const char *));
```

3. get base virtual address

```gdb
info proc map
# take first address
# 0x56206755e000     0x56206758b000    0x2d000        0x0 /usr/bin/bash
```

4. get current tty

```gdb
! tty
# /dev/pts/7
```

5. call

```gdb
print ((int*(*)(const char *))(0x56206755e000 + 0x00000000000e0420))("/dev/pts/7")
```


