#===== HEADER ==================================================================

cmake_minimum_required(VERSION 3.31)
project(dbg)

#===== MAIN EXECUTABLE =========================================================

add_executable(
    dbg
    src/main.cpp
    src/dbg.cpp
    src/breakpoint.cpp
    src/command.cpp
    src/debug_info.cpp
    src/registers.cpp
    src/tracee.cpp
    libs/linenoise/linenoise.c
)

target_compile_features(
    dbg
    PRIVATE cxx_std_26
)

set_target_properties(
    dbg
    PROPERTIES CXX_EXTENSIONS OFF
)

target_include_directories(
    dbg
    PRIVATE
        ${PROJECT_SOURCE_DIR}/include
        ${PROJECT_SOURCE_DIR}/libs/linenoise
        ${PROJECT_SOURCE_DIR}/libs/libelfin
)

#===== EXAMPLES ================================================================

add_executable(
    hello
    examples/hello.cpp
)

set_target_properties(
    hello
    PROPERTIES CXX_EXTENSIONS OFF
)

target_compile_features(
    hello
    PRIVATE cxx_std_26
)

target_compile_options(
    hello
    PRIVATE -g -gdwarf-2 -O0
)

add_executable(
    variable
    examples/variable.cpp
)

set_target_properties(
    variable
    PROPERTIES CXX_EXTENSIONS OFF
)

target_compile_features(
    variable
    PRIVATE cxx_std_26
)

target_compile_options(
    variable
    PRIVATE -gdwarf-2 -O0
)

add_executable(
    unwinding
    examples/stack_unwinding.cpp
)

set_target_properties(
    unwinding
    PROPERTIES CXX_EXTENSIONS OFF
)

target_compile_features(
    unwinding
    PRIVATE cxx_std_26
)

target_compile_options(
    unwinding
    PRIVATE -g -gdwarf-2 -O0
)

#===== DEPENDENCIES ============================================================

add_custom_target(
    libelfin
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libs/libelfin
)

target_link_libraries(
    dbg
    PRIVATE
    ${PROJECT_SOURCE_DIR}/libs/libelfin/dwarf/libdwarf++.so
    ${PROJECT_SOURCE_DIR}/libs/libelfin/elf/libelf++.so
)

add_dependencies(
    dbg
    libelfin
)
