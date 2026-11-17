bpf_objects()
bpf_object(plugin_a.c plugin_a3.o -DFACTOR=3)                # replaces plugin_a in the reload tests
bpf_object(shared_counter.c shared_counter_u32.o -DVALUE=u32) # mismatched shared map definition
