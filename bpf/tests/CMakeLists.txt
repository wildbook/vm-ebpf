bpf_objects()

# replaces plugin_a_v1 in the reload tests
bpf_object(plugin_a_v2 SOURCE plugin_a_v1.c DEFINITIONS FACTOR=3)
# mismatched shared map definition
bpf_object(shared_counter_u32 SOURCE shared_counter.c DEFINITIONS VALUE=u32)
# an extern that needs six argument registers
bpf_object(struct_args_six SOURCE struct_args.c DEFINITIONS TOO_MANY)
