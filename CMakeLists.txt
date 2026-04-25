cmake_minimum_required(VERSION 3.10)
project(zdbg C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID MATCHES "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
elseif(MSVC)
    add_compile_options(/W4)
endif()

# Core library: every module except main.c.
set(ZDBG_CORE_SOURCES
    src/arch.c
    src/arch_x86_64.c
    src/arch_aarch64.c
    src/arch_aarch64_dis.c
    src/regs.c
    src/regfile.c
    src/mem.c
    src/expr.c
    src/bp.c
    src/hwbp.c
    src/filter.c
    src/actions.c
    src/maps.c
    src/machine.c
    src/symbols.c
    src/tinyasm.c
    src/tinydis.c
    src/target.c
    src/target_null.c
    src/signal.c
    src/exception.c
    src/patch.c
    src/pe.c
    src/cmd.c
    src/repl.c
    src/stdio.c)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND ZDBG_CORE_SOURCES src/os_linux/target_linux.c)
    list(APPEND ZDBG_CORE_SOURCES src/os_linux/maps_linux.c)
    list(APPEND ZDBG_CORE_SOURCES src/os_linux/symbols_elf.c)
elseif(WIN32)
    list(APPEND ZDBG_CORE_SOURCES src/os_windows/target_windows.c)
endif()

add_library(zdbg_core STATIC ${ZDBG_CORE_SOURCES})
target_include_directories(zdbg_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(zdbg src/main.c)
target_link_libraries(zdbg PRIVATE zdbg_core)

# Example target program used for manual debugging sessions.
# Build at -O0 -g and keep symbols so the integration test (and
# manual sessions) can look up main/foo via ELF .symtab.
add_executable(testprog examples/testprog.c)
set_target_properties(testprog PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(testprog PRIVATE -O0 -g -fno-omit-frame-pointer)
endif()

# Tiny portable stdio echo target for io tests.
add_executable(testio examples/testio.c)
set_target_properties(testio PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")
if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
   CMAKE_C_COMPILER_ID MATCHES "Clang")
    target_compile_options(testio PRIVATE -O0 -g)
endif()

# Multi-threaded example for manual thread-awareness sessions
# and the optional Linux thread integration test.  Pthreads is
# the only external dependency, added just for this target.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Threads REQUIRED)
    add_executable(testthreads examples/testthreads.c)
    set_target_properties(testthreads PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")
    target_link_libraries(testthreads PRIVATE Threads::Threads)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
       CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(testthreads PRIVATE
            -O0 -g -fno-omit-frame-pointer)
    endif()

    add_executable(testsignals examples/testsignals.c)
    set_target_properties(testsignals PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU" OR
       CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(testsignals PRIVATE
            -O0 -g -fno-omit-frame-pointer)
    endif()
endif()

enable_testing()
add_subdirectory(tests)
