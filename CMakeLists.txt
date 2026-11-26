# Builds the BPF objects under bpf/ to build/bpf/<dir>/<name>.o. Cargo reads the copies committed under bpf/prebuilt/,
# so clang is only needed after changing a source or a header. BPF_CLANG names a clang other than the one on PATH:
#
#   cmake --preset bpf -DBPF_CLANG=<clang>
#   cmake --build --preset bpf
#   cmake --build --preset update-prebuilt
cmake_minimum_required(VERSION 3.21)
project(rvm_bpf LANGUAGES C)

if(NOT CMAKE_C_COMPILER_TARGET STREQUAL "bpf")
    message(FATAL_ERROR "Configure with cmake/bpf-toolchain.cmake, for example through `cmake --preset bpf`.")
endif()

# A build directory keeps the compiler that its first configuration found, with the version it had then.
# `cmake --fresh` finds it again.
if(NOT DEFINED BPF_CLANG_CONFIGURED)
    set(BPF_CLANG_CONFIGURED "${BPF_CLANG}" CACHE INTERNAL "BPF_CLANG at the first configuration")
endif()
if(NOT BPF_CLANG STREQUAL BPF_CLANG_CONFIGURED)
    message(FATAL_ERROR
        "This build directory compiles with ${BPF_CLANG_CONFIGURED}. Add --fresh to configure it for ${BPF_CLANG}.")
endif()

# rvm follows the calling convention of clang 23, which returns a struct of up to 16 bytes in r0 and r2. Older
# versions return it through a pointer in r1. 23.1.6 is the release the objects in bpf/prebuilt/ come from.
set(BPF_CLANG_MINIMUM 23.1.6)
if(NOT CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_VERSION VERSION_LESS BPF_CLANG_MINIMUM)
    message(FATAL_ERROR
        "The BPF objects need clang ${BPF_CLANG_MINIMUM} or newer, and ${CMAKE_C_COMPILER} is "
        "${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}. Name another one with -DBPF_CLANG=<clang>, and add "
        "--fresh if this build directory has seen an older clang.")
endif()

set(BPF_PREBUILT_DIR "${PROJECT_SOURCE_DIR}/bpf/prebuilt" CACHE PATH "Directory that update-prebuilt copies into")

# Both prefixes map to `.`, the repo root, so the debug info doesn't depend on the checkout or build path. The build
# directory can sit inside the source directory, so its map comes last; clang applies the last matching one.
#
# -fno-slp-vectorize: the BPF target has no vector instructions, and clang 23.1 crashes in BPF instruction selection
# on a signed vector division that its SLP vectorizer forms from the scalar divisions in corpus/matmul.c.
add_library(bpf_options INTERFACE)
target_compile_options(bpf_options INTERFACE
    -mcpu=v4 -O2 -g -fno-slp-vectorize
    "-ffile-prefix-map=${PROJECT_SOURCE_DIR}=."
    "-ffile-prefix-map=${PROJECT_BINARY_DIR}=.")
target_include_directories(bpf_options INTERFACE "${PROJECT_SOURCE_DIR}/bpf")

# Compiles <name>.c, or the SOURCE file, from the current directory into the object library <name>, with the
# DEFINITIONS.
function(bpf_object name)
    cmake_parse_arguments(PARSE_ARGV 1 arg "" "SOURCE" "DEFINITIONS")
    if(NOT arg_SOURCE)
        set(arg_SOURCE "${name}.c")
    endif()

    add_library("${name}" OBJECT "${arg_SOURCE}")
    target_link_libraries("${name}" PRIVATE bpf_options)
    target_compile_definitions("${name}" PRIVATE ${arg_DEFINITIONS})

    file(RELATIVE_PATH dir "${PROJECT_SOURCE_DIR}/bpf" "${CMAKE_CURRENT_SOURCE_DIR}")
    set_property(GLOBAL APPEND PROPERTY BPF_OBJECTS "${dir}/${name}")
endfunction()

# Calls bpf_object for each .c file in the current directory, named after the file.
function(bpf_objects)
    file(GLOB sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.c")
    foreach(source IN LISTS sources)
        cmake_path(GET source STEM name)
        bpf_object("${name}" SOURCE "${source}")
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
# inputs.sha256 lets `cargo test` notice sources that changed after the last update.
add_custom_target(update-prebuilt
    COMMAND "${CMAKE_COMMAND}" -E make_directory ${prebuilt_dirs}
    ${copy_commands}
    COMMAND "${CMAKE_COMMAND}" "-DSOURCE_DIR=${PROJECT_SOURCE_DIR}" "-DOUTPUT=${BPF_PREBUILT_DIR}/inputs.sha256"
        -P "${PROJECT_SOURCE_DIR}/cmake/hash-inputs.cmake"
    DEPENDS ${built_objects}
    VERBATIM)
