# Builds every BPF object next to its source. The objects are committed, so this is only needed after changing a
# source or a header.
#
#   cmake -S bpf -B .local/llm/tmp/bpf-build -G Ninja
#   cmake --build .local/llm/tmp/bpf-build
cmake_minimum_required(VERSION 3.20)
project(rvm_bpf LANGUAGES NONE)

find_program(CLANG clang REQUIRED)

set(BPF_FLAGS -target bpf -mcpu=v4 -O2 -g)
get_filename_component(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
file(GLOB BPF_HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/*/*.h")

# Compiles bpf/<source> to bpf/<object> with the extra flags in ARGN. Runs from the repo root with relative paths,
# so the paths recorded in the debug info don't depend on the checkout location.
function(bpf_object source object)
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/${object}"
        COMMAND "${CLANG}" ${BPF_FLAGS} ${ARGN} -c "bpf/${source}" -o "bpf/${object}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${source}" ${BPF_HEADERS}
        WORKING_DIRECTORY "${REPO_ROOT}"
        VERBATIM)
    list(APPEND BPF_OBJECTS "${CMAKE_CURRENT_SOURCE_DIR}/${object}")
    set(BPF_OBJECTS "${BPF_OBJECTS}" PARENT_SCOPE)
endfunction()

file(GLOB BPF_SOURCES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/bench/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c")
foreach(source IN LISTS BPF_SOURCES)
    string(REGEX REPLACE "\\.c$" ".o" object "${source}")
    bpf_object("${source}" "${object}")
endforeach()

# Variants of one source built with a different define.
bpf_object(examples/game_rules.c examples/game_rules_v2.o -DRULES_V2) # the hot-reload build in the modding example
bpf_object(tests/plugin_a.c tests/plugin_a3.o -DFACTOR=3)             # replaces plugin_a in the reload tests
bpf_object(tests/shared_counter.c tests/shared_counter_u32.o -DVALUE=u32) # mismatched shared map definition

add_custom_target(bpf ALL DEPENDS ${BPF_OBJECTS})
