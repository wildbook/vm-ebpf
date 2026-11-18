bpf_objects(rvm_bpf
    acq_rel.c
    atomics.c
    borrow_callee.c
    borrow_caller.c
    core_bitfield.c
    core_guard.c
    data_ptrs.c
    func_ptr.c
    global_hits.c
    guest_ptrs.c
    host_event.c
    link_lib.c
    link_main.c
    may_goto.c
    maps.c
    plugin_a.c
    plugin_b.c
    shared_counter.c
    shared_region.c
    std_helpers.c)

# replaces plugin_a in the reload tests
bpf_object(plugin_a3 SOURCE plugin_a.c LINK rvm_bpf DEFINITIONS FACTOR=3)
# mismatched shared map definition
bpf_object(shared_counter_u32 SOURCE shared_counter.c LINK rvm_bpf DEFINITIONS VALUE=u32)
