# CMake generated Testfile for 
# Source directory: /home/runner/work/zdbg/zdbg/tests
# Build directory: /home/runner/work/zdbg/zdbg/build-win/tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_expr "/home/runner/work/zdbg/zdbg/build-win/tests/test_expr.exe")
set_tests_properties(test_expr PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;3;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_tinyasm "/home/runner/work/zdbg/zdbg/build-win/tests/test_tinyasm.exe")
set_tests_properties(test_tinyasm PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;7;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_tinydis "/home/runner/work/zdbg/zdbg/build-win/tests/test_tinydis.exe")
set_tests_properties(test_tinydis PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;11;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_bp "/home/runner/work/zdbg/zdbg/build-win/tests/test_bp.exe")
set_tests_properties(test_bp PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;15;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_hwbp "/home/runner/work/zdbg/zdbg/build-win/tests/test_hwbp.exe")
set_tests_properties(test_hwbp PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;19;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_maps "/home/runner/work/zdbg/zdbg/build-win/tests/test_maps.exe")
set_tests_properties(test_maps PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;23;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_expr_maps "/home/runner/work/zdbg/zdbg/build-win/tests/test_expr_maps.exe")
set_tests_properties(test_expr_maps PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;27;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_symbols "/home/runner/work/zdbg/zdbg/build-win/tests/test_symbols.exe")
set_tests_properties(test_symbols PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;31;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_signal "/home/runner/work/zdbg/zdbg/build-win/tests/test_signal.exe")
set_tests_properties(test_signal PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;35;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_patch "/home/runner/work/zdbg/zdbg/build-win/tests/test_patch.exe")
set_tests_properties(test_patch PROPERTIES  _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;39;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
add_test(test_windows_target "/home/runner/work/zdbg/zdbg/build-win/tests/test_windows_target.exe")
set_tests_properties(test_windows_target PROPERTIES  ENVIRONMENT "ZDBG_TESTPROG=/home/runner/work/zdbg/zdbg/build-win/examples/testprog.exe" _BACKTRACE_TRIPLES "/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;76;add_test;/home/runner/work/zdbg/zdbg/tests/CMakeLists.txt;0;")
