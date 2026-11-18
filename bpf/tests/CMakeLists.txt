bpf_objects()

# replaces plugin_a in the reload tests
bpf_object(plugin_a3 SOURCE plugin_a.c DEFINITIONS FACTOR=3)
# mismatched shared map definition
bpf_object(shared_counter_u32 SOURCE shared_counter.c DEFINITIONS VALUE=u32)
