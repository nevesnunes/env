# compiler flags - includes, libraries

```
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

# Reference:
# https://gcc.gnu.org/onlinedocs/cpp/Environment-Variables.html
```

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

foo(const map<string, string>& bar)
map::at()

# temporary default values

-fsanitize-address-use-after-scope

# synchronization with volatile

std::atomics, mutex

# thread safety

shared_ptr<T>
    ok: reference count, control block
    ko: T
    ko: shared_ptr pointers

atomic<shared_ptr>

# shadow declaration

// RAII types + default constructor
std::string(foo);

-Wshadow
// good but ko: -Wshadow-compatible-local
unique_lock<mutex> g(m_mutex);

---

# Testing

ctest -VV

# Packaging

cpack
    generates: CPackConfig.cmake

set(CMAKE_DEBUG_POSTFIX "-d")

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

### cmake

```
file://~/code/snippets/*.cmake
```

https://github.com/boostcon/cppnow_presentations_2017/blob/master/05-19-2017_friday/effective_cmake__daniel_pfeifer__cppnow_05-19-2017.pdf

ExternalProject_Add() + add_subdirectory()
find_package()

add_library()
target_link_library()
    logical dependencies
    public vs private
        => workaround cyclic dependencies
        public -target-prop-> LINK_LIBRARIES, INTERFACE_LINK_LIBRARIES
        private -target-prop-> LINK_LIBRARIES

phases
    build
        CMAKE_BUILD_TYPE
    config
        generator expressions
            target_compile_definitions()
            e.g. $<IF:$<CONFIG:Debug>:foo,bar>

hierarchy
    add_subdirectory()
        requires CMakeLists.txt

scripts
    cmake -P foo.cmake

modules
    include()
        requires CMAKE_MODULE_PATH

variables
    undefined => expands to empty string
    not in environment

targets
    constructors
        - add_executable()
        - add_library()
    member variables
        - target properties
    member functions
        - get_target_property()
        - set_target_properties()
        - get_property(TARGET)
        - set_property(TARGET)
        - target_compile_definitions()
        - target_compile_features()
        - target_compile_options()
        - target_include_directories()
        - target_link_libraries()
        - target_sources()

---

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
