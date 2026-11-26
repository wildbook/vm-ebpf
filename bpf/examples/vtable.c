/*
 * Calls the host through a table of function pointers, the way a C plugin API hands its functions out. The host in
 * lib/rvm/examples/vtable.rs loads this plugin untagged and with raw calls, so `api` and the pointers the plugin
 * passes are plain host addresses.
 */
#include "rvm_bpf.h"

struct size {
    u32 width;
    u32 height;
};

/* `HostApi` in the host. */
struct host_api {
    u64 (*version)(void);
    void (*log)(const char *text, u64 len);
    void (*window_size)(struct size *out);
    u64 (*scale)(u64 value, u64 numerator, u64 denominator);
};

/* Logs a line, asks for the window size, which the host writes to this stack, and returns a tenth of its area. */
u64 run(const struct host_api *api) {
    static const char hello[] = "hello from the plugin";
    struct size size;

    if (api->version() < 2)
        return 0;
    api->log(hello, sizeof(hello) - 1);
    api->window_size(&size);
    return api->scale(size.width, size.height, 10);
}
