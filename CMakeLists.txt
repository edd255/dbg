cmake_minimum_required(VERSION 3.0)
project(dbg)
add_compile_options(-std=c++14)
include_directories(
    ext/libelfin
    libs/linenoise
    include
)
add_executable(
    dbg 
    src/main.cpp
    src/debugger.cpp
    src/breakpoint.hpp
    src/registers.cpp
    libs/linenoise/linenoise.c
)
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
add_dependencies(dbg libelfin)
