# * detects if, say, libpng is available
# * compile a library, an executable and a unit test if that's the case
# * links the executable to the library and the library to libpng
# * does so for mac, windows, linux, creates a .app for mac, an installer for windows, a .deb package for linux

cmake_minimum_required(VERSION 3.8)
project(myapp)

find_package(PNG REQUIRED)

add_library(mylib lib.c)
add_executable(myapp MACOS_BUNDLE WIN32 app.c)

# [optional] config
target_compile_features(mylib PUBLIC cxx_std_17)
target_include_directories(mylib PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(mylib PRIVATE PNG::PNG)
target_link_libraries(myapp PRIVATE mylib)

install(
  TARGETS myapp mylib 
  RUNTIME DESTINATION bin 
  ARCHIVE DESTINATION lib)
include(CPack)
