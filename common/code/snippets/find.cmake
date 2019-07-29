find_path(Foo_INCLUDE_DIR foo.h)
find_library(Foo_LIBRARY foo)
mark_as_advanced(Foo_INCLUDE_DIR Foo_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Foo
    REQUIRED_VARS Foo_LIBRARY Foo_INCLUDE_DIR
    )

if(Foo_FOUND AND NOT TARGET Foo::Foo)
    add_library(Foo::Foo UNKNOWN IMPORTED)
    set_target_properties(Foo::Foo PROPERTIES
        IMPORTED_LINK_INTERFACE_LANGUAGES "CXX"
        IMPORTED_LOCATION "${ Foo_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${ Foo_INCLUDE_DIR}"
        )
endif()
