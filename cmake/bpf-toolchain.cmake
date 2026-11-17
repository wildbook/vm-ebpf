# Compiles C for the BPF target with clang. BPF objects are relocatable ELF files that are never linked, so the
# compiler check builds a static library instead of an executable.
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR bpf)

set(CMAKE_C_COMPILER clang)
set(CMAKE_C_COMPILER_TARGET bpf)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
