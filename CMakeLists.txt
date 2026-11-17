# Builds the BPF objects under bpf/. The objects are committed, so this is only needed after changing a source or a
# header. The Rust crates build with cargo.
#
#   cmake -S . -B .local/llm/tmp/cmake -G Ninja
#   cmake --build .local/llm/tmp/cmake
cmake_minimum_required(VERSION 3.20)
project(rvm LANGUAGES NONE)

find_program(CLANG clang REQUIRED)
set(BPF_FLAGS -target bpf -mcpu=v4 -O2 -g)

# Compiles <source> in the current directory to <object> next to it, with the extra flags in ARGN. Runs from the repo
# root with relative paths, so the paths recorded in the debug info don't depend on the checkout location.
function(bpf_object source object)
    file(RELATIVE_PATH dir "${PROJECT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
    file(GLOB headers CONFIGURE_DEPENDS "${PROJECT_SOURCE_DIR}/bpf/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
    add_custom_command(
        OUTPUT "${CMAKE_CURRENT_SOURCE_DIR}/${object}"
        COMMAND "${CLANG}" ${BPF_FLAGS} ${ARGN} -c "${dir}/${source}" -o "${dir}/${object}"
        DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/${source}" ${headers}
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
        VERBATIM)
    set_property(DIRECTORY APPEND PROPERTY BPF_OBJECTS "${CMAKE_CURRENT_SOURCE_DIR}/${object}")
endfunction()

# Compiles every .c file in the current directory to a .o file of the same name. At the end of the directory, a target
# named after it builds these and any bpf_object variants listed there; custom command outputs are only visible to
# targets of the same directory.
function(bpf_objects)
    file(GLOB sources RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
    foreach(source IN LISTS sources)
        string(REGEX REPLACE "\\.c$" ".o" object "${source}")
        bpf_object("${source}" "${object}")
    endforeach()
    cmake_language(DEFER CALL bpf_target)
endfunction()

function(bpf_target)
    file(RELATIVE_PATH dir "${PROJECT_SOURCE_DIR}" "${CMAKE_CURRENT_SOURCE_DIR}")
    string(REPLACE "/" "_" name "${dir}")
    get_property(objects DIRECTORY PROPERTY BPF_OBJECTS)
    add_custom_target("${name}" ALL DEPENDS ${objects})
endfunction()

add_subdirectory(bpf)
