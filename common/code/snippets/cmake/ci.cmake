set(CTEST_SOURCE_DIRECTORY "/source")
set(CTEST_BINARY_DIRECTORY "/binary")

set(ENV{CXXFLAGS} "--coverage")
set(CTEST_CMAKE_GENERATOR "Ninja")
set(CTEST_USE_LAUNCHERS 1)

set(CTEST_COVERAGE_COMMAND "gcov")
set(CTEST_MEMORYCHECK_COMMAND "valgrind")
set(CTEST_MEMORYCHECK_TYPE "ThreadSanitizer")

ctest_start("Continuous")
ctest_configure()
ctest_build()
ctest_test()
ctest_coverage()
ctest_memcheck()
ctest_submit()
