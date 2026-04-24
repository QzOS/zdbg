add_executable(test_expr test_expr.c)
target_link_libraries(test_expr PRIVATE zdbg_core)
add_test(NAME test_expr COMMAND test_expr)

add_executable(test_tinyasm test_tinyasm.c)
target_link_libraries(test_tinyasm PRIVATE zdbg_core)
add_test(NAME test_tinyasm COMMAND test_tinyasm)

add_executable(test_tinydis test_tinydis.c)
target_link_libraries(test_tinydis PRIVATE zdbg_core)
add_test(NAME test_tinydis COMMAND test_tinydis)

add_executable(test_bp test_bp.c)
target_link_libraries(test_bp PRIVATE zdbg_core)
add_test(NAME test_bp COMMAND test_bp)

add_executable(test_maps test_maps.c)
target_link_libraries(test_maps PRIVATE zdbg_core)
add_test(NAME test_maps COMMAND test_maps)

add_executable(test_expr_maps test_expr_maps.c)
target_link_libraries(test_expr_maps PRIVATE zdbg_core)
add_test(NAME test_expr_maps COMMAND test_expr_maps)

add_executable(test_symbols test_symbols.c)
target_link_libraries(test_symbols PRIVATE zdbg_core)
add_test(NAME test_symbols COMMAND test_symbols)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(test_linux_target test_linux_target.c)
    target_link_libraries(test_linux_target PRIVATE zdbg_core)
    add_test(NAME test_linux_target COMMAND test_linux_target)

    add_executable(test_linux_bp test_linux_bp.c)
    target_link_libraries(test_linux_bp PRIVATE zdbg_core)
    add_test(NAME test_linux_bp COMMAND test_linux_bp)

    add_executable(test_linux_symbols test_linux_symbols.c)
    target_link_libraries(test_linux_symbols PRIVATE zdbg_core)
    add_test(NAME test_linux_symbols COMMAND test_linux_symbols)
    set_tests_properties(test_linux_symbols PROPERTIES
        ENVIRONMENT "ZDBG_TESTPROG=$<TARGET_FILE:testprog>")
endif()
