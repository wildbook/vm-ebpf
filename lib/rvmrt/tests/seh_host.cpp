// A C++ host of rvmrt.dll built with the `seh` feature, for tests/seh.rs: loads the image of bpf/tests/seh.c that the
// test prepared, makes its natives fault, and checks that each call fails and the program stays callable.
//
//   seh_host <image file>

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "rvmrt.h"

static int destroyed;

struct Counted {
    ~Counted() { destroyed++; }
};

static uint64_t nat_strlen(uint64_t text) { return strlen((const char *)text); }

static uint64_t nat_raise(uint64_t code, uint64_t flags, uint64_t count, uint64_t args) {
    RaiseException((DWORD)code, (DWORD)flags, (DWORD)count, (const ULONG_PTR *)args);
    return 0;
}

static uint64_t nat_break(void) { return 0; }

static uint64_t nat_sort(uint64_t base, uint64_t count, uint64_t size, uint64_t compare) {
    qsort((void *)base, count, size, (int (*)(const void *, const void *))compare);
    return 0;
}

// Throws below a frame that owns an object with a destructor.
static uint64_t nat_throw(uint64_t x) {
    Counted counted;
    if (x != 0)
        throw std::runtime_error("nat_throw");
    return x;
}

#pragma optimize("", off)
// Recurses until the stack overflows.
static uint64_t nat_recurse(uint64_t depth) {
    volatile char pad[256];
    pad[0] = (char)depth;
    return nat_recurse(depth + 1) + pad[0];
}
#pragma optimize("", on)

static rvm_native native(const char *name, const void *func, uint8_t args) {
    rvm_native n = {name, strlen(name), func, args, {0}, {0}};
    return n;
}

static rvm_program *program;
static int failures;

static void check(const char *what, bool ok) {
    printf("%s: %s\n", what, ok ? "ok" : "FAILED");
    failures += !ok;
}

static rvm_status call(const char *name, std::vector<uint64_t> args, uint64_t *ret) {
    return rvm_call(program, name, strlen(name), args.data(), args.size(), ret);
}

// Whether the call of `name` fails with an exception of `code` in a native function.
static bool raises(const char *name, uint64_t arg, uint32_t code) {
    uint64_t ret;
    uint32_t raised = 0;
    uint64_t address = 0;
    return call(name, {arg}, &ret) == RVM_ERR_FAULT && rvm_last_exception(program, &raised, &address) == RVM_OK &&
           raised == code && address != 0;
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 2;
    FILE *file = nullptr;
    if (fopen_s(&file, argv[1], "rb") != 0)
        return 2;
    std::vector<uint8_t> image(1 << 20);
    image.resize(fread(image.data(), 1, image.size(), file));
    fclose(file);

    const rvm_native natives[] = {
        native("nat_strlen", (const void *)nat_strlen, 1), native("nat_raise", (const void *)nat_raise, 4),
        native("nat_break", (const void *)nat_break, 0),   native("nat_sort", (const void *)nat_sort, 4),
        native("nat_throw", (const void *)nat_throw, 1),   native("nat_recurse", (const void *)nat_recurse, 1),
    };
    const size_t count = sizeof(natives) / sizeof(natives[0]);
    check("an unknown flag is refused",
          rvm_load_with(image.data(), image.size(), natives, count, 8, &program) == RVM_ERR_ARGUMENT);
    const uint32_t flags = RVM_RAW_POINTERS | RVM_CATCH_NATIVE | RVM_CATCH_RAW;
    if (rvm_load_with(image.data(), image.size(), natives, count, flags, &program) != RVM_OK) {
        printf("load FAILED\n");
        return 1;
    }

    uint32_t code;
    uint64_t address, ret = 0;
    check("no exception before any call", rvm_last_exception(program, &code, &address) == RVM_ERR_NOT_FOUND);

    // reserved and never committed, so every access to it is an access violation
    uint64_t unmapped = (uint64_t)VirtualAlloc(nullptr, 1 << 16, MEM_RESERVE, PAGE_NOACCESS);
    uint64_t value = 41;

    for (int round = 1; round <= 2; round++) {
        printf("round %d\n", round);
        check("a null read in a native fails the call", raises("text_len", 0, 0xC0000005));
        check("a raised exception fails the call", raises("raise", 0xE0000001, 0xE0000001));
        check("a C++ exception fails the call", raises("throw", 1, 0xE06D7363));
        check("the destructor below the throw ran", destroyed == round);
        check("a stack overflow in a native fails the call", raises("recurse", 0, 0xC00000FD));
        check("a load of an unmapped raw address fails the call", call("load64", {unmapped}, &ret) == RVM_ERR_FAULT);
        check("a store to an unmapped raw address fails the call",
              call("store32", {unmapped + 8, 1}, &ret) == RVM_ERR_FAULT);

        check("the native works afterwards", call("text_len", {(uint64_t) "four"}, &ret) == RVM_OK && ret == 5);
        check("a raw load works afterwards", call("load64", {(uint64_t)&value}, &ret) == RVM_OK && ret == 41);
        uint64_t values[2] = {2, 1};
        auto ascending = [](const void *a, const void *b) -> int { return *(const uint64_t *)a > *(const uint64_t *)b; };
        int (*compare)(const void *, const void *) = ascending;
        check("a native that calls back works",
              call("sort", {(uint64_t)values, (uint64_t)compare}, &ret) == RVM_OK && values[0] == 1);
    }

    rvm_free(program);
    return failures != 0;
}
