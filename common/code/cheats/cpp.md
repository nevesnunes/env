# repl

```bash
printf 'int main(){}' | gcc -o /tmp/1 -x c - && gdb /tmp/1 -ex 'b main' -ex 'r'
```

# building

```bash
# Optional: Outputs `configure`
autoreconf -fi
./configure
make
sudo make install
# ||
make prefix="$HOME/foo" install
```

### position-independent code

```bash
gcc -fPIE -pie
# vs.
gcc -no-pie -fno-pic
```

# 32bit vs 64bit binary

- IA-32, a variant of x86, commonly known as i386 (the name used by Debian) or i686 (which, like IA-32, are generations of the x86 architecture series)
- x86-64, also known as x64 or amd64 (the name used by Debian) (not to be confused with IA-64 which is completely different)

```bash
od -An -t x1 -j 4 -N 1 foo
# Output: 01 if 32bit, 02 if 64bit
```

References:

- https://unix.stackexchange.com/questions/125295/32-bit-vs-64-bit-vs-arm-in-regards-to-programs-and-oses

# debug info

`strip` - removes symbol names

# language servers - clangd

```bash
cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

# || From build commands
# References: https://github.com/rizsotto/Bear
bear make

# Validation
test -f compile_commands.json
```

# compiler

### testing

```bash
printf '#include<stdio.h>
int main() { puts("Hi!"); return 0; }' \
    | i686-linux-musl-gcc -xc - \
    && ./a.out; rm -f a.out
```

### includes, libraries

```bash
# create shared library
gcc foo.c -o foo -shared -fPIC

# both c and c++
./configure \
    CPPFLAGS="-I/foo" \
    CPATH="/foo"

# only c
./configure \
    CFLAGS="-I/foo" \
    C_INCLUDE_PATH="/foo"

# only c++
./configure \
    CXXFLAGS="-I/foo" \
    CPLUS_INCLUDE_PATH="/foo"

# include library `libfoo.so.*`
LIBS=-lfoo ./configure

# include specific library version
LIBS=-l:libfoo.so.123 ./configure
```

https://gcc.gnu.org/onlinedocs/cpp/Environment-Variables.html

#### MinGW GCC support

```bash
reimp.exe -d foo.lib
dlltool.exe -k -d foo.def -l foo.a
```

- https://trinitycore.atlassian.net/wiki/spaces/tc/pages/2130053/MinGW+GCC+toolchain+Win
- https://wiki.tcl-lang.org/page/How+to+create+mingw32+libraries+from+DLLs
- https://stackoverflow.com/questions/2472924/linking-to-msvc-dll-from-mingw

### override include

On /include/foo.h:

```c
#include "foo.h"
#include "bar.h"
```

CPPFLAGS="-I/include"

### guards

https://stackoverflow.com/questions/31115366/make-error-multiple-definitions-of-despite-include-guard

### GNU extensions

https://stackoverflow.com/questions/10613126/what-are-the-differences-between-std-c11-and-std-gnu11

### static build

```bash
# With configure
./configure "LDFLAGS=--static"
env CXXFLAGS=-static --enable-static --disable-shared -fPIC --prefix="$(pwd)" make

# With Makefile
make CC=./mips64-linux-musl-cross/bin/mips64-linux-musl-gcc LDFLAGS=-static
./mips64-linux-musl-cross/bin/mips64-linux-musl-gcc -O -Wall -std=c90 -c hello.c
./mips64-linux-musl-cross/bin/mips64-linux-musl-gcc -static -o hello hello.o
```

- musl
    - stdenv, REALGCC
        - [Musl dynamic linked binary use glibc dynamic linker \(not musl\) · Issue \#25178 · NixOS/nixpkgs · GitHub](https://github.com/NixOS/nixpkgs/issues/25178)
    ```bash
    docker pull alpine
    docker run -it -v "$HOME/share:/share:z" alpine
    apk add --no-cache gcc musl-dev
    ```
- Unsupported in `libtool`
    - [\#11064 \- CRITICAL: libtool makes static linking impossible \- GNU bug report logs](https://debbugs.gnu.org/cgi/bugreport.cgi?bug=11064)
    - [Configuration does not generate statically linked executable · Issue \#632 · esnet/iperf · GitHub](https://github.com/esnet/iperf/issues/632)

# tooling

clang-tidy
ASAN
    gcc -fuse-ld=gold
    gcc -g -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -static-libasan
valgrind --vgdb=full --vgdb-error=0 ./a.out

cpplint
clazy
include-what-you-use -Xiwyu

gcov
https://www.cdash.org/

gcc -ggdb3
gdb, cgdb
    -D_FORTIFY_SOURCE=1
    python gdb.execute()
    python gdb.parser_and_eval()
    python help('gdb')
lldb
rr
undodb
live recorder

perf, sysprof
valgrind --trace-children=yes
ftrace
    trace-cmd
strace -k
    prints backtrace

https://github.com/dalance/flexlint

http://www.mingw.org/wiki/MS_resource_compiler

https://chromium.googlesource.com/chromium/src.git/+/master/docs/linux/eclipse_dev.md

---

# gdb

https://github.com/CppCon/CppCon2018/blob/master/Presentations/liberating_the_debugging_experience_with_the_gdb_python_api/liberating_the_debugging_experience_with_the_gdb_python_api__jeff_trull__cppcon_2018.pdf

uses `ptrace`

info signals
    when to stop, print, pass to inferior
handle SIGINT stop print nopass

thread apply all backtrace full

gdbserver localhost:2000 ./a.out
target remote localhost:2000

### reverse debugging

```
b main
b _exit
command 1
record
command 2
run

reverse-stepi
```

rr replay

### watchpoints

watch foo               stop when foo is modified
watch -l foo            watch location
rwatch foo              stop when foo is read
watch foo thread 3      stop when thread 3 modifies foo
watch foo if foo > 10   stop when foo is> 1O

### Dynamic Printf

Use dprintf to put printf's in your code without recompiling.
    e.g. dprintf mutex_lock,"m is %p m->magic is %u\n",m,m->magic

Control how the printfs happen:

set dprintf-style gdb|call|agent
set dprintf-function fprintf
set dprintf-channel mylog

### errno

```gdb
print *((int*(*)())__errno_location)()
```

# valgrind

Cachegrind: cache profiler. simulates l1, D1, L2 caches
Callgrind: like cachegrind, but also with call-graphs
Massif: heap profiler
Helgrind: find race conditions in multithreaded programs
DRD: Data Race Detector. Like Helgrind, but uses less memory.
Lackey / None: demo/unit test of valgrind itself.

---

# out-of-bounds

-fsanitize=address

# typo key initialization

```cpp
foo(const map<string, string>& bar)
map::at()
```

# temporary default values

-fsanitize-address-use-after-scope

# synchronization with volatile

```cpp
std::atomics, mutex
```

# unbuffered stream

```cpp
setbuf(stdout, NULL);
```

# thread safety

```cpp
shared_ptr<T>
    ok: reference count, control block
    ko: T
    ko: shared_ptr pointers

atomic<shared_ptr>
```

# shadow declaration

```cpp
// RAII types + default constructor
std::string(foo);

// -Wshadow
// good but ko: -Wshadow-compatible-local
unique_lock<mutex> g(m_mutex);
```

---

# Dependencies

### vcpkg

https://vcpkg.readthedocs.io/en/latest/

### conan

conan info ..
conan search gtest -r conan-center

Decentralized servers
- OSS, corporate, private, etc
Central cache on local PC
- sharing of the dependencies data among different projects
Support for
- sources only (do not use prebuilt binaries even if available)
- sources + prebuilt binaries (improves build performance)
- binaries only (for closed source projects and development tools)
Offline use

# space-efficient algorithms

heavy hitters, majority element, boyer-moore's majority vote
    elements that occur at least x% of the time
    e.g. throttle users with multiple requests

morris traversal
    O(1) space tree traversal
    e.g. free children without recursion

reservoir sampling
    given a stream of data, select k items at random
    e.g. biggrep

HyperLogLog
    count number of distinct elements by leading zeros, partition input space, apply harmonic mean

# STL

`#include <algorithm>`

adjacent_find
partitions
partial_sort
    ~= nth_element + sort
rotate
gather
    = 2 stable_partition, pair inserted in point
set_difference

# stable

preserve prior ordering whenever there is a conflict
e.g. priority queue for same values

# comparison

https://en.wikipedia.org/wiki/Sorting_algorithm#Comparison_of_algorithms

# bjam

sudo dnf install -y boost-build boost-devel boost-jam boost-python3-devel python3-devel
sudo ln -fs /usr/bin/bjam /usr/bin/b2
sudo ln -fs /usr/lib64/libpython3.7m.so /usr/lib64/libpython3.7.so
source ~/code/sand/boost-build/profile.sh

# debug

```c
#define protected public
#define private public
#include <foo.h>
```

assert state has not changed between function calls

# windows

```bash
# crosscompiling from linux to exe for 32-bit
i686-w64-mingw32-gcc 646.c -lws2_32 -o 646.exe
```

https://virtuallyfun.com/wordpress/2020/02/01/cross-compiling-sdl-1-2-15-for-arm-win32/

```
C:\proj\ss\SDL-1.2.15\VisualC\SDL>link /dll -out:sdl.dll *.obj winmm.lib dxguid.lib gdi32.lib user32.lib advapi32.lib dxguid.lib uuid.lib dxguid.lib Version.res
Microsoft (R) Incremental Linker Version 14.24.28315.0
Copyright (C) Microsoft Corporation. All rights reserved.

Creating library sdl.lib and object sdl.exp
SDL_dx5events.obj : error LNK2001: unresolved external symbol GUID_SysMouse
```

```bash
strings ~/Downloads/dxguid.lib | grep GUID_SysMouse
# Output:
# _GUID_SysMouse
```

https://github.com/tpn/winsdk-10/blob/9b69fd26ac0c7d0b83d378dba01080e93349c2ed/Include/10.0.16299.0/um/dinput.h#L117

```c
DEFINE_GUID(GUID_SysMouse, 0x6F1D2B60,0xD5A0,0x11CF,0xBF,0xC7,0x44,0x45,0x53,0x54,0x00,0x00);
```

https://github.com/tpn/winsdk-10/blob/master/Include/10.0.10240.0/shared/guiddef.h#L59

```c
#ifndef DECLSPEC_SELECTANY
#if (_MSC_VER >= 1100)
#define DECLSPEC_SELECTANY  __declspec(selectany)
#else
#define DECLSPEC_SELECTANY
#endif
#endif

// ...

#ifdef INITGUID
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    EXTERN_C const GUID DECLSPEC_SELECTANY name \
        = { l, w1, w2, { b1, b2,  b3,  b4,  b5,  b6,  b7,  b8 } }
#else
#define DEFINE_GUID(name, l, w1, w2, b1, b2, b3, b4, b5, b6, b7, b8) \
    EXTERN_C const GUID FAR name
#endif // INITGUID
```

https://docs.microsoft.com/en-us/cpp/cpp/declspec?view=vs-2019
https://stackoverflow.com/questions/2284610/what-is-declspec-and-when-do-i-need-to-use-it

=> define INITGUID

# case studies

IOCCC's Best Abuse of the Rules in 1988
    ```c
    #include "/dev/tty"
    ```
    > it waits for you to type c code at your terminal, then compiles that. /dev/tty is the device representing the current terminal and can be read or written like a regular file
    - https://twitter.com/eevee/status/678720136061169664

### build issues

[Undefined reference \`\_\_powf\_finite\` with clang 9\.0\.1, Linux 5\.5\.4\-arch1\-1 and glibc 2\.31\-1 · Issue \#2146 · google/filament · GitHub](https://github.com/google/filament/issues/2146)
[c \- What exactly is \-fno\-builtin doing here? \- Stack Overflow](https://stackoverflow.com/questions/54281780/what-exactly-is-fno-builtin-doing-here)
[Audacity &\#8211; New Major Release &\#8211; Compile Fix, for Portaudio\.\. &\#8211; Adventures With Linux ™](http://rglinuxtech.com/?p=2093)
