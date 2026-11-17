add_library(game_sdk INTERFACE)
target_include_directories(game_sdk INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(game_sdk INTERFACE rvm_bpf)

bpf_objects(rvm_bpf core_example.c example.c msgpack_logs.c)
bpf_objects(game_sdk game_combat.c game_rules.c)

# the hot-reload build in the modding example
bpf_object(game_rules_v2 SOURCE game_rules.c LINK game_sdk DEFINITIONS RULES_V2)
