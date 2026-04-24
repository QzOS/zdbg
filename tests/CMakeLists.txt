add_executable(test_expr test_expr.c)
target_link_libraries(test_expr PRIVATE zdbg_core)
add_test(NAME test_expr COMMAND test_expr)

add_executable(test_tinyasm test_tinyasm.c)
target_link_libraries(test_tinyasm PRIVATE zdbg_core)
add_test(NAME test_tinyasm COMMAND test_tinyasm)

add_executable(test_tinydis test_tinydis.c)
target_link_libraries(test_tinydis PRIVATE zdbg_core)
add_test(NAME test_tinydis COMMAND test_tinydis)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_linux_target test_linux_target.c)
    target_link_libraries(test_linux_target PRIVATE zdbg_core)
    add_test(NAME test_linux_target COMMAND test_linux_target)
endif()
