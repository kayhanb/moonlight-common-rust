// CPUID feature checks for nanors under clang-cl (see cpu_shim.h).
//
// Covers the features nanors asks for. AVX2 and AVX-512 also require the OS to
// save the wider register state (OSXSAVE + XCR0), like compiler-rt checks.
#include <intrin.h>
#include <string.h>

static int os_saves_ymm(void) {
    int info[4];
    __cpuid(info, 1);
    if (!(info[2] & (1 << 27))) {
        return 0;
    }
    return (_xgetbv(0) & 0x6) == 0x6;
}

static int os_saves_zmm(void) {
    return os_saves_ymm() && (_xgetbv(0) & 0xe6) == 0xe6;
}

int mcs_cpu_supports(const char* feature) {
    int info[4];
    __cpuid(info, 0);
    int max_leaf = info[0];

    if (strcmp(feature, "ssse3") == 0) {
        __cpuid(info, 1);
        return (info[2] >> 9) & 1;
    }
    if (max_leaf < 7) {
        return 0;
    }
    __cpuidex(info, 7, 0);
    if (strcmp(feature, "avx2") == 0) {
        return ((info[1] >> 5) & 1) && os_saves_ymm();
    }
    if (strcmp(feature, "avx512f") == 0) {
        return ((info[1] >> 16) & 1) && os_saves_zmm();
    }
    if (strcmp(feature, "gfni") == 0) {
        return (info[2] >> 8) & 1;
    }
    return 0;
}
