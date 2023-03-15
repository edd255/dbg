#===== HEADER ==================================================================

cmake_minimum_required(VERSION 3.0)
project(dbg)
add_compile_options(-std=c++14)

#===== MAIN EXECUTABLE =========================================================

include_directories(
    ext/libelfin
    libs/linenoise
    include
)

add_executable(
    dbg 
    src/dbg.cpp
    libs/linenoise/linenoise.c
)

#===== EXAMPLES ================================================================

add_executable(
    hello
    examples/hello.cpp
)

set_target_properties(
    hello
    PROPERTIES COMPILE_FLAGS "-g -gdwarf-2 -O0"
)

add_executable(
    variable
    examples/variable.cpp
)

set_target_properties(
    variable
    PROPERTIES COMPILE_FLAGS "-gdwarf-2 -O0"
)

add_executable(
    unwinding
    examples/stack_unwinding.cpp
)

set_target_properties(
    unwinding
    PROPERTIES COMPILE_FLAGS "-g -gdwarf-2 -O0"
)

#===== DEPENDENCIES ============================================================

add_custom_target(
    libelfin
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/libs/libelfin
)

target_link_libraries(
    dbg
    ${PROJECT_SOURCE_DIR}/libs/libelfin/dwarf/libdwarf++.so
    ${PROJECT_SOURCE_DIR}/libs/libelfin/elf/libelf++.so
)

add_dependencies(
    dbg
    libelfin
)
