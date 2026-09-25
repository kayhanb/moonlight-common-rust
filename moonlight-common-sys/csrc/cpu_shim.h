// Force-included into moonlight-common-c when targeting MSVC (see build.rs).
//
// nanors picks its SIMD path with __builtin_cpu_supports(). Under clang-cl that
// builtin reads compiler-rt's __cpu_model, which is not linked for the MSVC
// target, so the final link fails with an undefined __cpu_model. nanors only
// ships its own CPUID fallback for cl.exe (_MSC_VER without __clang__), so
// clang-cl is routed to the equivalent in cpu_shim.c instead.
#if defined(_MSC_VER) && defined(__clang__)
int mcs_cpu_supports(const char* feature);
#define __builtin_cpu_supports mcs_cpu_supports
#endif
