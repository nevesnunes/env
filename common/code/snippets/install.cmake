find_package(Bar 2.0 REQUIRED)
add_library(Foo ...)
target_link_libraries(Foo PRIVATE Bar::Bar)

install(TARGETS Foo EXPORT FooTargets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
    )
install(EXPORT FooTargets
    FILE FooTargets.cmake
    NAMESPACE Foo::
    DESTINATION lib/cmake/Foo
    )

include(CMakePackageConfigHelpers)
write_basic_package_version_file("FooConfigVersion.cmake"
    VERSION ${F00_VERSION}
    COMPATIBILITY SameMajorVersion
    )

install(FILES "FooConfig.cmake" "FooConfigVersion.cmake"
    DESTINATION Lib/Cmake/Foo
    )

# Installable file

include(CMakeFindDependencyMacro)
find_dependency(Bar 2.0)
include("${CMAKE_CURRENT_LIST_DIR}/FooTargets.cmake")
