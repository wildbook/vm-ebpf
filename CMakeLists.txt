# Builds the BPF objects under bpf/ to build/bpf/<dir>/<name>.o. Cargo reads the copies committed under bpf/prebuilt/,
# so clang is only needed after changing a source or a header:
#
#   cmake --preset bpf
#   cmake --build --preset bpf
#   cmake --build --preset update-prebuilt
cmake_minimum_required(VERSION 3.21)
project(rvm_bpf LANGUAGES C)

if(NOT CMAKE_C_COMPILER_TARGET STREQUAL "bpf")
    message(FATAL_ERROR "Configure with cmake/bpf-toolchain.cmake, for example through `cmake --preset bpf`.")
endif()

set(BPF_PREBUILT_DIR "${PROJECT_SOURCE_DIR}/bpf/prebuilt" CACHE PATH "Directory that update-prebuilt copies into")

# Both prefixes map to `.`, the repo root, so the debug info doesn't depend on the checkout or build path. The build
# directory can sit inside the source directory, so its map comes last; clang applies the last matching one.
add_library(bpf_options INTERFACE)
target_compile_options(bpf_options INTERFACE
    -mcpu=v4 -O2 -g
    "-ffile-prefix-map=${PROJECT_SOURCE_DIR}=."
    "-ffile-prefix-map=${PROJECT_BINARY_DIR}=.")

# Compiles <name>.c, or the SOURCE file, from the current directory into the object library <name>, using the header
# library LINK and the DEFINITIONS.
function(bpf_object name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "SOURCE;LINK" "DEFINITIONS")
    if(NOT arg_SOURCE)
        set(arg_SOURCE "${name}.c")
    endif()

    add_library("${name}" OBJECT "${arg_SOURCE}")
    target_link_libraries("${name}" PRIVATE bpf_options "${arg_LINK}")
    target_compile_definitions("${name}" PRIVATE ${arg_DEFINITIONS})

    file(RELATIVE_PATH dir "${PROJECT_SOURCE_DIR}/bpf" "${CMAKE_CURRENT_SOURCE_DIR}")
    set_property(GLOBAL APPEND PROPERTY BPF_OBJECTS "${dir}/${name}")
endfunction()

# Calls bpf_object for each source, named after the file.
function(bpf_objects link)
    foreach(source IN LISTS ARGN)
        cmake_path(GET source STEM name)
        bpf_object("${name}" SOURCE "${source}" LINK "${link}")
    endforeach()
endfunction()

add_subdirectory(bpf)

# CMake names objects <target>.dir/<source>.obj, so each one is copied to a stable path, and from there to the
# prebuilt directory.
get_property(objects GLOBAL PROPERTY BPF_OBJECTS)
foreach(object IN LISTS objects)
    cmake_path(GET object FILENAME name)
    set(built "${PROJECT_BINARY_DIR}/bpf/${object}.o")
    set(prebuilt "${BPF_PREBUILT_DIR}/${object}.o")
    add_custom_command(
        OUTPUT "${built}"
        COMMAND "${CMAKE_COMMAND}" -E copy "$<TARGET_OBJECTS:${name}>" "${built}"
        DEPENDS "${name}" "$<TARGET_OBJECTS:${name}>"
        VERBATIM)
    list(APPEND built_objects "${built}")

    cmake_path(GET prebuilt PARENT_PATH prebuilt_dir)
    list(APPEND prebuilt_dirs "${prebuilt_dir}")
    list(APPEND copy_commands COMMAND "${CMAKE_COMMAND}" -E copy "${built}" "${prebuilt}")
endforeach()
add_custom_target(bpf-objects ALL DEPENDS ${built_objects})

list(REMOVE_DUPLICATES prebuilt_dirs)
add_custom_target(update-prebuilt
    COMMAND "${CMAKE_COMMAND}" -E make_directory ${prebuilt_dirs}
    ${copy_commands}
    DEPENDS ${built_objects}
    VERBATIM)
