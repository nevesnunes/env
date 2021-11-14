# +

~/code/snippets/*.cmake

(mkdir -p build && cd build && cmake .. && make)

https://github.com/boostcon/cppnow_presentations_2017/blob/master/05-19-2017_friday/effective_cmake__daniel_pfeifer__cppnow_05-19-2017.pdf

ExternalProject_Add() + add_subdirectory()
find_package()

link_directories()
add_library()
target_link_library()
    logical dependencies
    public vs private
        => workaround cyclic dependencies
        public -target-prop-> LINK_LIBRARIES, INTERFACE_LINK_LIBRARIES
        private -target-prop-> LINK_LIBRARIES
    [!] order sensitive - https://stackoverflow.com/questions/38530491/undefined-reference-to-function-cmake

phases
    build
        [CMAKE_BUILD_TYPE](https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html)
    config
        generator expressions
            target_compile_definitions()
            e.g. `$<IF:$<CONFIG:Debug>:foo,bar>`
    install
        [CMAKE_INSTALL_PREFIX](https://cmake.org/cmake/help/latest/variable/CMAKE_INSTALL_PREFIX.html)

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

# Compiler

c++ vs g++

### Flags

```bash
cmake -DCMAKE_CXX_FLAGS="-std=c++14"
```

# Debug

```bash
cmake --help-module FindPkgConfig

cmake --trace --debug-output --debug-trycompile
cmake -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON ..
make VERBOSE=1
```

### Symbols

```cmake
set(CMAKE_BUILD_TYPE Debug)
```

```bash
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake -DCMAKE_BUILD_TYPE=Debug
```

# Stack Size

```cmake
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,stack-size=1000000")
```

# Include Conflicts

```c
#ifdef __WXGTK20__
#define GSocket GlibGSocket
#include <gtk-2.0/gtk/gtk.h>
#undef GSocket
#endif
```

# Overrides

```bash
bin_overrides=$(mktemp -d) && \
ln -s /usr/lib64/wx/config/gtk2-unicode-3.0 "$bin_overrides/wx-config" && \
PATH="$bin_overrides":$PATH

export WX_CONFIG=/usr/lib64/wx/config/gtk2-unicode-3.0
```

### Flags

```cmake
IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Release ... FORCE )
ENDIF()
```

- https://stackoverflow.com/questions/23907679/cmake-ignores-d-cmake-build-type-debug

# Find Libraries

```cmake
link_directories( /root/foo/ )
set(PROJECT_LINK_LIBS libFoo.so)
add_executable(hello ${SOURCES})
target_link_libraries(hello ${PROJECT_LINK_LIBS} )
```

https://stackoverflow.com/questions/31438916/cmake-cannot-find-library-using-link-directories

find_library()
=> uses CMAKE_PREFIX_PATH, CMAKE_LIBRARY_PATH
-- https://gitlab.kitware.com/cmake/community/-/wikis/doc/cmake/Useful-Variables
e.g.
```
▬▬▬▬ grep -rin '\(include_directories\|link_directories\|target_link_libraries\).*zmusic'
./src/CMakeLists.txt:29:                link_directories( ${ZMUSIC_ROOT_PATH}/64bit )
./src/CMakeLists.txt:31:                link_directories( ${ZMUSIC_ROOT_PATH}/32bit )
./src/CMakeLists.txt:440:include_directories( "${ZLIB_INCLUDE_DIR}" "${BZIP2_INCLUDE_DIR}" "${LZMA_INCLUDE_DIR}" "${JPEG_INCLUDE_DIR}" "${ZMUSIC_INCLUDE_DIR}" )
./src/CMakeLists.txt:1244:target_link_libraries( zdoom ${ZDOOM_LIBS} gdtoa lzma ${ZMUSIC_LIBRARIES} )
▬▬▬▬ grep -rin 'ZMUSIC_LIBRARIES'
./cmake/FindZMusic.cmake:5:#  ZMUSIC_LIBRARIES   - List of libraries when using ZMusic
./cmake/FindZMusic.cmake:8:if(ZMUSIC_INCLUDE_DIR AND ZMUSIC_LIBRARIES)
./cmake/FindZMusic.cmake:15:find_library(ZMUSIC_LIBRARIES NAMES zmusic)
./cmake/FindZMusic.cmake:16:mark_as_advanced(ZMUSIC_LIBRARIES ZMUSIC_INCLUDE_DIR)
./cmake/FindZMusic.cmake:21:find_package_handle_standard_args(ZMusic DEFAULT_MSG ZMUSIC_LIBRARIES ZMUSIC_INCLUDE_DIR)
```

# Testing

```bash
ctest -VV
```

# Packaging

```bash
# Generates: `CPackConfig.cmake`
cpack
```


