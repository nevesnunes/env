cmake_minimum_required(VERSION 3.8)
project(MyLibraryTests)

# dependencies
enable_testing()
find_package(GTest MODULE REQUIRED)
if(NOT TARGET MyCompany::MyLibrary)
    find_package(MyLibrary CONFIG REQUIRED)
endif()

# target definition
add_executable(MyLibraryTests tests_source.cpp)
target_link_libraries(HyLibraryTests
    PRIVATE
    MyCompany::MyLibrary
    GTest::Main
    )
add_test(NAME MyLibrary.UnitTests
    COMMAND MyLibraryTests
    )
