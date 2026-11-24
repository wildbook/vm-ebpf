bpf_objects()

# the hot-reload build in the modding example
bpf_object(game_rules_v2 SOURCE game_rules_v1.c DEFINITIONS RULES_V2)
# version 2 in the hot_reload example
bpf_object(counter_v2 SOURCE counter_v1.c DEFINITIONS COUNTER_V2)
