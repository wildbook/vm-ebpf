# Compiles C for the BPF target with clang. BPF objects are relocatable ELF files that are never linked, so the
# compiler check builds a static library instead of an executable.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR bpf)

# A name on PATH or a full path: `cmake --preset bpf -DBPF_CLANG=<clang>`. CMake reads this file again in the
# projects of its compiler checks, which get the variable through CMAKE_TRY_COMPILE_PLATFORM_VARIABLES.
set(BPF_CLANG clang CACHE STRING "The clang that compiles the BPF objects, version 23 or newer")
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES BPF_CLANG)

set(CMAKE_C_COMPILER "${BPF_CLANG}")
set(CMAKE_C_COMPILER_TARGET bpf)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
