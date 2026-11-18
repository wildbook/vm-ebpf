# Writes OUTPUT with a "<sha256>  <path>" line for each input of the BPF objects under SOURCE_DIR, sorted by path.
# CRLF line ends are hashed as LF, so a checkout with either gives the same hashes. lib/rvm/src/bpf_sources.rs
# computes the same list.
#
#   cmake -DSOURCE_DIR=<repo> -DOUTPUT=<file> -P cmake/hash-inputs.cmake
file(GLOB_RECURSE bpf_inputs RELATIVE "${SOURCE_DIR}"
    "${SOURCE_DIR}/bpf/*.c" "${SOURCE_DIR}/bpf/*.h" "${SOURCE_DIR}/bpf/CMakeLists.txt")
file(GLOB cmake_inputs RELATIVE "${SOURCE_DIR}" "${SOURCE_DIR}/CMakeLists.txt" "${SOURCE_DIR}/cmake/*.cmake")
set(inputs ${bpf_inputs} ${cmake_inputs})
list(SORT inputs)

set(lines "")
foreach(input IN LISTS inputs)
    file(READ "${SOURCE_DIR}/${input}" text)
    string(REPLACE "\r\n" "\n" text "${text}")
    string(SHA256 hash "${text}")
    string(APPEND lines "${hash}  ${input}\n")
endforeach()
file(WRITE "${OUTPUT}" "${lines}")
