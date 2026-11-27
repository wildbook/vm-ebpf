// A C host of rvmrt.dll for tests/stack_args.rs: loads the prepared image of bpf/tests/rvmrt_stack_args.c and checks
// calls with 6 to 12 arguments through rvm_call, rvm_call_func, rvm_native (including a checked pointer on the stack)
// and RVM_RAW_CALLS.
//
//   stack_args_host <image file>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rvmrt.h"

static uint64_t weigh(const uint64_t *args, size_t n) {
    uint64_t total = 0;
    for (size_t i = 0; i < n; i++)
        total += args[i] * (uint64_t)(i + 1);
    return total;
}

static uint64_t n6(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f) {
    uint64_t args[6] = {a, b, c, d, e, f};
    return weigh(args, 6);
}

static uint64_t n12(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, uint64_t g, uint64_t h,
                    uint64_t i, uint64_t j, uint64_t k, uint64_t l) {
    uint64_t args[12] = {a, b, c, d, e, f, g, h, i, j, k, l};
    return weigh(args, 12);
}

static uint64_t n_buf(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e, uint64_t f, const uint8_t *buf,
                      uint64_t len) {
    uint64_t args[6] = {a, b, c, d, e, f};
    uint64_t total = weigh(args, 6);
    for (uint64_t i = 0; i < len; i++)
        total += buf[i];
    return total;
}

static int failures;

static void check(const char *what, bool ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAILED");
    failures += !ok;
}

static rvm_status call(rvm_program *program, const char *name, const uint64_t *args, size_t nargs, uint64_t *ret) {
    return rvm_call(program, name, strlen(name), args, nargs, ret);
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    FILE *file = NULL;
    if (fopen_s(&file, argv[1], "rb") != 0)
        return 2;
    uint8_t *image = (uint8_t *)malloc(1 << 20);
    if (!image) {
        fclose(file);
        return 2;
    }
    size_t len = fread(image, 1, 1 << 20, file);
    fclose(file);

    rvm_native natives[3] = {
        {"n6", 2, (const void *)n6, 6, {0}, {0}},
        {"n12", 3, (const void *)n12, 12, {0}, {0}},
        {"n_buf", 5, (const void *)n_buf, 8, {0, 0, 0, 0, 0, 0, RVM_ARG_READ, 0}, {0, 0, 0, 0, 0, 0, 8, 0}},
    };
    rvm_options options = {
        .size = sizeof(rvm_options),
        .natives = natives,
        .native_count = 3,
        .flags = RVM_RAW_CALLS,
    };

    rvm_program *program = NULL;
    if (rvm_load_with(image, len, &options, &program) != RVM_OK) {
        printf("load FAILED\n");
        free(image);
        return 1;
    }

    uint64_t args13[13];
    for (size_t i = 0; i < 13; i++)
        args13[i] = 7 + i;

    uint64_t ret = 0;
    check("rvm_call with 6 args", call(program, "g6", args13, 6, &ret) == RVM_OK && ret == weigh(args13, 6));
    check("rvm_call with 12 args", call(program, "g12", args13, 12, &ret) == RVM_OK && ret == weigh(args13, 12));
    check("rvm_call with 13 args is rejected", call(program, "g12", args13, 13, &ret) == RVM_ERR_ARGUMENT);

    size_t g12_idx = 0;
    check("rvm_func finds g12", rvm_func(program, "g12", 3, &g12_idx) == RVM_OK);
    check("rvm_call_func with 12 args",
          rvm_call_func(program, g12_idx, args13, 12, &ret) == RVM_OK && ret == weigh(args13, 12));

    uint64_t x = 9;
    uint64_t from_x[12];
    for (size_t i = 0; i < 12; i++)
        from_x[i] = x + i;

    check("native n6", call(program, "call_n6", &x, 1, &ret) == RVM_OK && ret == weigh(from_x, 6));
    check("native n12", call(program, "call_n12", &x, 1, &ret) == RVM_OK && ret == weigh(from_x, 12));

    uint64_t buf_ok[2] = {x, 4};
    check("native n_buf checked pointer on stack",
          call(program, "call_n_buf", buf_ok, 2, &ret) == RVM_OK && ret == weigh(from_x, 6) + 1 + 2 + 3 + x);

    uint64_t buf_bad[2] = {x, 1 << 20};
    check("native n_buf overrun faults", call(program, "call_n_buf", buf_bad, 2, &ret) == RVM_ERR_FAULT);

    uint64_t raw6_args[2] = {(uint64_t)(uintptr_t)n6, x};
    check("raw call with 6 args", call(program, "raw6", raw6_args, 2, &ret) == RVM_OK && ret == weigh(from_x, 6));

    uint64_t raw12_args[2] = {(uint64_t)(uintptr_t)n12, x};
    check("raw call with 12 args", call(program, "raw12", raw12_args, 2, &ret) == RVM_OK && ret == weigh(from_x, 12));

    rvm_free(program);
    free(image);
    return failures != 0;
}
