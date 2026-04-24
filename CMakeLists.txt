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
    src/regs.c
    src/mem.c
    src/expr.c
    src/bp.c
    src/tinyasm.c
    src/tinydis.c
    src/target.c
    src/target_null.c
    src/cmd.c
    src/repl.c)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(APPEND ZDBG_CORE_SOURCES src/os_linux/target_linux.c)
elseif(WIN32)
    list(APPEND ZDBG_CORE_SOURCES src/os_windows/target_windows.c)
endif()

add_library(zdbg_core STATIC ${ZDBG_CORE_SOURCES})
target_include_directories(zdbg_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_executable(zdbg src/main.c)
target_link_libraries(zdbg PRIVATE zdbg_core)

# Example target program used for manual debugging sessions.
add_executable(testprog examples/testprog.c)
set_target_properties(testprog PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples")

enable_testing()
add_subdirectory(tests)
