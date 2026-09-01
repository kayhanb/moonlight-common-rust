#include <stdarg.h>
#include <stdio.h>

/* Implemented in Rust (moonlight-common-sys/src/lib.rs). */
extern void moonlight_sys_rust_log(const char *message);

/*
 * moonlight-common-c logs through a printf-style variadic callback. Rust can
 * declare variadic C functions but cannot define them on stable, so the
 * formatting happens here and the finished string is handed to Rust.
 */
void moonlight_sys_log_message(const char *format, ...) {
    char buffer[2048];
    va_list args;

    va_start(args, format);
    vsnprintf(buffer, sizeof buffer, format, args);
    va_end(args);

    moonlight_sys_rust_log(buffer);
}
