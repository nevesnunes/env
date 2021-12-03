# explain

- [cdecl: C gibberish &harr; English](https://cdecl.org/)

# repl

```bash
gdb /bin/true -ex 'b main' -ex 'r'
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

### pkgconfig

- `PKG_CONFIG_PATH` set to path containing .pc files

### position-independent code

```bash
gcc -fPIE -pie
# vs.
gcc -no-pie -fno-pic
```

- https://unix.stackexchange.com/questions/89211/how-to-test-whether-a-linux-binary-was-compiled-as-position-independent-code
- https://codywu2010.wordpress.com/2014/11/29/about-elf-pie-pic-and-else/

# 32bit vs 64bit binary

- IA-32, a variant of x86, commonly known as i386 (the name used by Debian) or i686 (which, like IA-32, are generations of the x86 architecture series)
- x86-64, also known as x64 or amd64 (the name used by Debian) (not to be confused with IA-64 which is completely different)

```bash
od -An -t x1 -j 4 -N 1 foo
# Output: 01 if 32bit, 02 if 64bit
```

References:

- https://unix.stackexchange.com/questions/125295/32-bit-vs-64-bit-vs-arm-in-regards-to-programs-and-oses

# following syscall references in libc

- https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86/time.c.html
    - if [vDSO](https://man7.org/linux/man-pages/man7/vdso.7.html) available:
        ```c
        _dl_vdso_vsym ("__vdso_time", &linux26) ?:  &__time_syscall
        ```
    - else fallback on syscall:
        ```c
        static time_t __time_syscall (time_t *t) {
          INTERNAL_SYSCALL_DECL (err);
          return INTERNAL_SYSCALL (time, err, 1, t);
        }
        ```
- https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sysdep.h.html#234
    - redirect to syscall macro (e.g. nr=1 if arg1 passed)
        ```c
        #define INTERNAL_SYSCALL(name, err, nr, args...) \
                internal_syscall##nr (SYS_ify (name), err, args)
        ```
- https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/x86_64/sysdep.h.html
    - convert syscall name to nr
        ```c
        /* For Linux we can use the system call table in the header file /usr/include/asm/unistd.h of the kernel.  But these symbols do not follow the SYS_* syntax so we have to redefine the `SYS_ify' macro here.  */
        #undef SYS_ify
        #define SYS_ify(syscall_name) __NR_##syscall_name
        ```
    - check which table to lookup based on arch
        ```c
        # ifdef __i386__
        #  include <asm/unistd_32.h>
        # elif defined(__ILP32__)
        #  include <asm/unistd_x32.h>
        # else
        #  include <asm/unistd_64.h>
        # endif
        ```
    - lookup syscall nr in table
        ```c
        #define __NR_time 201
        ```

# name mangling, name decoration

```bash
# GCC / Clang
c++filt
# MSVC
undname '?func1@a@@AAEXH@Z'
# Watcom
# https://github.com/open-watcom/open-watcom-v2/blob/master/bld/lib_misc/c/demangle.c
demangle 'W?h$n(i)v'
```

- https://docs.microsoft.com/en-us/cpp/build/reference/decorated-names?view=msvc-160

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
    LDFLAGS="-L/foo/usr/lib" \
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

    # From package sources
    # References:
    # - https://unix.stackexchange.com/questions/496755/how-to-get-the-source-code-used-to-build-the-packages-of-the-base-alpine-linux-d
    # - https://wiki.alpinelinux.org/wiki/Creating_an_Alpine_package
    # - https://wiki.alpinelinux.org/wiki/APKBUILD_Reference
    app=
    apk add --no-cache alpine-sdk gcc musl-dev sudo
    cd /opt
    git clone --depth 1 --branch v3.13.1 git://git.alpinelinux.org/aports
    cd ./aports/main/"$app"
    # Override pkg-config dependencies (e.g. when specifying static libs)
    # References: [Static compilation errors \- tmux 2\.9, ncurses 6\.1, libevent 2\.1\.8 · Issue \#1729 · tmux/tmux · GitHub](https://github.com/tmux/tmux/issues/1729)
    export PKG_CONFIG=/bin/true
    # [Edit APKBUILD to include `-static` in CFLAGS]
    abuild-keygen -a -i
    abuild -F fetch verify
    abuild -F -r
    tar -xzvf /root/packages/main/x86_64/"$app".apk
    ```
- Unsupported in `libtool`
    - [\#11064 \- CRITICAL: libtool makes static linking impossible \- GNU bug report logs](https://debbugs.gnu.org/cgi/bugreport.cgi?bug=11064)
    - [Configuration does not generate statically linked executable · Issue \#632 · esnet/iperf · GitHub](https://github.com/esnet/iperf/issues/632)

# tooling

- clang-tidy
- ASAN
    - gcc -fuse-ld=gold
    - gcc -g -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer -static-libasan
- valgrind --vgdb=full --vgdb-error=0 ./a.out

- cpplint
- clazy
- include-what-you-use -Xiwyu

- gcov
- https://www.cdash.org/

- gcc -ggdb3
- gdb, cgdb
    ```
    -D_FORTIFY_SOURCE=1
    python gdb.execute()
    python gdb.parser_and_eval()
    python help('gdb')
    ```
- lldb
- rr
- undodb
- live recorder

- perf, sysprof
- valgrind --trace-children=yes
- ftrace: trace-cmd
- strace -k

- [GitHub \- dalance/flexlint: A flexible linter with rules defined by regular expression](https://github.com/dalance/flexlint)
- [Finding Number Related Memory Corruption Vulns](https://maxwelldulin.com/BlogPost?post=9715056640)
    ```
    -ftrapv
    -fsanitize=integer,float-cast-overflow
    ```

- http://www.mingw.org/wiki/MS_resource_compiler
- https://chromium.googlesource.com/chromium/src.git/+/master/docs/linux/eclipse_dev.md

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

https://devblogs.microsoft.com/cppblog/finding-bugs-with-addresssanitizer-msvc-compiler/

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
# crosscompiling from linux to 32-bit exe
i686-w64-mingw32-gcc foo.c -lws2_32 -o foo.exe
# crosscompiling from linux to 64-bit exe
x86_64-w64-mingw32-gcc foo.c -lws2_32 -o foo.exe
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

### early exit bugs

```c
mutex.lock();
// ...
if (foo) {
    return; // missed unlock call
}
// ...
mutex.unlock();
```

# undefined behaviour

- Validation
    - `gcc foo.c -fdump-tree-all -O3`
    - /usr/include/limits.h
- Integer overflow as a result of adding two int type variables
    ```c
    int add(int a, int b) {
        if (a > 0 && b > 0) {
            // if (a + b < 0) { // can be optimized out
            if (a >= 0 ? b > INT_MAX - a : b < INT_MIN - a) {
                printf("%s\n", "overflow");
                return 0;
            }
        }
        return a + b;
    }
    ```
- Product overflow check: `n * m * sizeof(int) < PTRDIFF_MAX`
    - https://godbolt.org/z/PuCbFz
        - `PTRDIFF_MAX / sizeof(int) / n >= m`
    - https://godbolt.org/z/QXPYsp
        ```c
        #include <stdint.h>
        #include <stdlib.h>

        _Bool f(size_t m, size_t n)
        {
            return
                n <= SIZE_MAX / (2 * sizeof(int)) &&
                m <= SIZE_MAX / (2 * sizeof(int) * n);
        }
        ```
- Prefer SecureZeroMemory, explicit_bzero over memset
    - [35C3 \- Memsad \- YouTube](https://www.youtube.com/watch?v=0WzjAKABSDk)
    - [CWE-14: Compiler Removal of Code to Clear Buffers](https://cwe.mitre.org/data/definitions/14.html)
- [AppSec EU 2017 Dangerous Optimizations And The Loss Of Causality by Robert C  Seacord \- YouTube](https://www.youtube.com/watch?v=cjQQCrQ_wvs)
- [Schr&\#246;dinger's Code \- ACM Queue](https://queue.acm.org/detail.cfm?id=3468263)

# Qt

```cpp
connect(manager, SIGNAL(finished(QNetworkReply*)), this,
                 SLOT(replyFinished(QNetworkReply*)));

void NetworkHandler::replyFinished(QNetworkReply *reply) {
  qDebug() << reply->readAll();
}

void debugRequest(QNetworkRequest request, QByteArray data = QByteArray()) {
  qDebug() << request.url().toString();
  const QList<QByteArray>& rawHeaderList(request.rawHeaderList());
  foreach (QByteArray rawHeader, rawHeaderList) {
    qDebug() << request.rawHeader(rawHeader);
  }
  qDebug() << data;
}
```
