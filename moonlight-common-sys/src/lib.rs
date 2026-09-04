#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{
    ffi::CStr,
    os::raw::c_char,
    sync::atomic::{AtomicPtr, Ordering},
};

pub mod limelight {
    include!(concat!(env!("OUT_DIR"), "/limelight.rs"));
}

pub type LogMessageHandler = fn(&str);

static LOG_MESSAGE_HANDLER: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());

/// Installs the handler that receives formatted moonlight-common-c log lines.
/// Passing `None` silences the log output.
pub fn set_log_message_handler(handler: Option<LogMessageHandler>) {
    let pointer = handler.map_or(std::ptr::null_mut(), |handler| handler as *mut ());
    LOG_MESSAGE_HANDLER.store(pointer, Ordering::Release);
}

unsafe extern "C" {
    /// printf-style variadic log callback for `_CONNECTION_LISTENER_CALLBACKS::logMessage`.
    /// Defined in `csrc/log_shim.c`; it formats the message and forwards the
    /// result to [`set_log_message_handler`].
    pub fn moonlight_sys_log_message(format: *const c_char, ...);
}

#[unsafe(no_mangle)]
extern "C" fn moonlight_sys_rust_log(message: *const c_char) {
    let pointer = LOG_MESSAGE_HANDLER.load(Ordering::Acquire);
    if pointer.is_null() || message.is_null() {
        return;
    }

    // SAFETY: the pointer was produced from a `LogMessageHandler` in
    // `set_log_message_handler` and function pointers are never freed.
    let handler: LogMessageHandler = unsafe { std::mem::transmute(pointer) };
    // SAFETY: the C side passes a NUL-terminated buffer that outlives this call.
    let text = unsafe { CStr::from_ptr(message) }.to_string_lossy();

    handler(text.trim_end_matches(['\r', '\n']));
}

unsafe extern "C" {
    /// Monotonic microsecond counter used by moonlight-common-c itself for the
    /// `receiveTimeUs`/`enqueueTimeUs` fields of `DECODE_UNIT`.
    ///
    /// Declared in `moonlight-common-c/src/Platform.h`, which is not part of
    /// the public header bindgen reads, so it is declared here by hand. Its
    /// epoch is the first call to `PltTicksInit` and therefore unrelated to any
    /// clock the caller has; only differences between two values are meaningful.
    fn PltGetMicroseconds() -> u64;
}

/// Reads moonlight-common-c's own microsecond clock.
///
/// Only useful for subtracting from the timestamps carried by `DECODE_UNIT`
/// (both use the same implementation-defined epoch).
pub fn now_micros() -> u64 {
    // SAFETY: the C function reads a monotonic clock and has no preconditions.
    unsafe { PltGetMicroseconds() }
}
