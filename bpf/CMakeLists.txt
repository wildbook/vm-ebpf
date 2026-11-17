add_library(rvm_bpf INTERFACE)
target_include_directories(rvm_bpf INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(examples)
add_subdirectory(bench)
add_subdirectory(tests)
