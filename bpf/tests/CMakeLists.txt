bpf_objects()

# replaces plugin_a_v1 in the reload tests
bpf_object(plugin_a_v2 SOURCE plugin_a_v1.c DEFINITIONS FACTOR=3)
# replaces callbacks in the callback reload tests
bpf_object(callbacks_v2 SOURCE callbacks.c DEFINITIONS FACTOR=10)
# mismatched shared map definition
bpf_object(shared_counter_u32 SOURCE shared_counter.c DEFINITIONS VALUE=u32)
# an extern that needs 13 argument registers
bpf_object(struct_args_thirteen SOURCE struct_args.c DEFINITIONS TOO_MANY)
