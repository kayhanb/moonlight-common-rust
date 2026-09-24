use std::{
    ffi::c_void,
    ops::Deref,
    os::raw::c_int,
    ptr::null_mut,
    slice,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, channel},
    },
    time::Duration,
};

use moonlight_common_sys::limelight::{
    _DECODER_RENDERER_CALLBACKS, LiCompleteVideoFrame, LiPollNextVideoFrame,
    LiWaitForNextVideoFrame, PDECODE_UNIT, VIDEO_FRAME_HANDLE,
};
use num::FromPrimitive;
use smallvec::SmallVec;
use thiserror::Error;
use tracing::debug;

use crate::stream::{
    ColorSpace, VideoFormats,
    c::bindings::Capabilities,
    video::{
        BufferType, DecodeResult, FrameIndex, FrameType, VideoCapabilities, VideoDecodeUnit,
        VideoDecoder, VideoFormat, VideoFrameBuffer, VideoSetup,
    },
};

static GLOBAL_VIDEO_DECODER: Mutex<Option<Box<dyn VideoDecoder + Send + 'static>>> =
    Mutex::new(None);

/// Runs `f` with the global decoder if one is installed.
///
/// Returns `None` when no decoder is set. Callers are `extern "C"` callbacks
/// invoked by moonlight-common-c, and a panic cannot unwind across that
/// boundary — it aborts the whole process. moonlight-common-c can still
/// deliver callbacks while a stream is being torn down (and a second stream
/// in the same process re-installs the globals), so "no decoder right now"
/// is a normal state that must be tolerated rather than asserted.
///
/// A poisoned mutex is also recovered from: the data it guards is an
/// `Option<Box<dyn ...>>` that stays valid, and refusing to lock would turn
/// one panic into an abort on every later callback.
fn global_decoder<R>(f: impl FnOnce(&mut dyn VideoDecoder) -> R) -> Option<R> {
    let mut lock = match GLOBAL_VIDEO_DECODER.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };
    let decoder = lock.as_mut()?;
    Some(f(decoder.as_mut()))
}

pub(crate) fn set_global(decoder: impl VideoDecoder + Send + 'static) {
    let mut global_video_decoder = match GLOBAL_VIDEO_DECODER.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };

    *global_video_decoder = Some(Box::new(decoder));
}
pub(crate) fn clear_global() {
    let mut decoder = match GLOBAL_VIDEO_DECODER.lock() {
        Ok(lock) => lock,
        Err(poisoned) => poisoned.into_inner(),
    };

    *decoder = None;
}

#[allow(non_snake_case)]
unsafe extern "C" fn setup(
    videoFormat: c_int,
    width: c_int,
    height: c_int,
    redrawRate: c_int,
    _context: *mut c_void,
    _drFlags: c_int,
) -> c_int {
    global_decoder(|decoder| {
        let setup = VideoSetup {
            format: VideoFormat::from_i32(videoFormat).expect("invalid video format"),
            width: width as u32,
            height: height as u32,
            redraw_rate: redrawRate as u32,
        };

        decoder.setup(setup)
    })
    // No decoder installed (teardown/restart): report success so the C side
    // continues its own shutdown instead of treating this as a failure.
    .unwrap_or(0)
}
unsafe extern "C" fn start() {
    global_decoder(|decoder| {
        decoder.start();
    });
}

unsafe extern "C" fn submit_decode_unit(decode_unit: PDECODE_UNIT) -> c_int {
    let unit = unsafe { convert_decode_unit(decode_unit) };

    // No decoder (teardown in progress): report success so moonlight-common-c
    // finishes shutting the stream down instead of retrying.
    global_decoder(|decoder| decoder.submit_decode_unit(unit) as i32).unwrap_or(0)
}
/// Converts the cpp decode unit into the rust one
unsafe fn convert_decode_unit<'a>(decode_unit: PDECODE_UNIT) -> VideoDecodeUnit<&'a [u8]> {
    let raw = unsafe { *decode_unit };

    let mut buffers = SmallVec::new();

    let mut next_element_ptr = raw.bufferList;
    while !next_element_ptr.is_null() {
        unsafe {
            let element_raw = *next_element_ptr;

            let new_element =
                slice::from_raw_parts(element_raw.data as *const u8, element_raw.length as usize);
            buffers.push(VideoFrameBuffer {
                buffer_type: BufferType::from_i32(element_raw.bufferType)
                    .expect("valid buffer type"),
                data: new_element,
            });

            next_element_ptr = element_raw.next;
        }
    }

    VideoDecodeUnit {
        frame_number: FrameIndex(raw.frameNumber as u32),
        frame_type: FrameType::from_i32(raw.frameType).expect("valid frame type"),
        // The field is in 1/10 ms units; converting it to whole milliseconds
        // rounded every sub-millisecond latency down to zero.
        frame_processing_latency: if raw.frameHostProcessingLatency == 0 {
            None
        } else {
            Some(Duration::from_micros(
                raw.frameHostProcessingLatency as u64 * 100,
            ))
        },
        receive_duration: Some(Duration::from_micros(
            raw.enqueueTimeUs.saturating_sub(raw.receiveTimeUs),
        )),
        // Read here, in the callback, because this is the moment the decoder
        // gets the frame: with CAPABILITY_DIRECT_SUBMIT this is the depacketizer
        // thread and the delay is ~0, without it the frame sat in the decode
        // unit queue until the VideoDec thread woke up.
        queue_duration: Some(Duration::from_micros(
            moonlight_common_sys::now_micros().saturating_sub(raw.enqueueTimeUs),
        )),
        // presentationTimeUs is in MICROSECONDS (Limelight.h); the 90 kHz
        // conversion belongs to rtpTimestamp and inflated every timestamp by
        // ~11x when applied here.
        timestamp: Duration::from_micros(raw.presentationTimeUs),
        color_space: ColorSpace::from_u8(raw.colorspace).expect("valid Colorspace"),
        buffers,
    }
}

unsafe extern "C" fn stop() {
    global_decoder(|decoder| {
        decoder.stop();
    });
}

unsafe extern "C" fn cleanup() {
    clear_global();
}

pub(crate) unsafe fn raw_callbacks() -> _DECODER_RENDERER_CALLBACKS {
    let video_capabilities = global_decoder(|decoder| decoder.capabilities()).unwrap_or_default();

    let mut capabilities = Capabilities::empty();
    if video_capabilities.pull_renderer {
        capabilities |= Capabilities::PULL_RENDERER;
    }
    // Mutually exclusive with PULL_RENDERER (Connection.c refuses both).
    if video_capabilities.direct_submit && !video_capabilities.pull_renderer {
        capabilities |= Capabilities::DIRECT_SUBMIT;
    }
    if video_capabilities.reference_frame_invalidation_h264 {
        capabilities |= Capabilities::REFERENCE_FRAME_INVALIDATION_AVC;
    }
    if video_capabilities.reference_frame_invalidation_h265 {
        capabilities |= Capabilities::REFERENCE_FRAME_INVALIDATION_HEVC;
    }
    if video_capabilities.reference_frame_invalidation_av1 {
        capabilities |= Capabilities::REFERENCE_FRAME_INVALIDATION_AV1;
    }

    let mut raw_capabilities = capabilities.bits();
    if let Some(slices) = video_capabilities.slices_per_frame {
        raw_capabilities |= slices_per_frame_capability(slices);
    }

    _DECODER_RENDERER_CALLBACKS {
        setup: Some(setup),
        start: Some(start),
        stop: Some(stop),
        cleanup: Some(cleanup),
        submitDecodeUnit: if capabilities.contains(Capabilities::PULL_RENDERER) {
            None
        } else {
            Some(submit_decode_unit)
        },
        capabilities: raw_capabilities as i32,
    }
}

/// `CAPABILITY_SLICES_PER_FRAME(x)` from Limelight.h. It is a function-like
/// macro, so bindgen does not generate it: the slice count lives in the top
/// byte of the capabilities, and moonlight-common-c asks the host for that many
/// slices per frame (`x-nv-video[0].videoEncoderSlicesPerFrame`). Zero means
/// "not set" there and falls back to one slice.
fn slices_per_frame_capability(slices: u32) -> u32 {
    slices.min(u32::from(u8::MAX)) << 24
}

pub struct PullVideoDecoder {
    setup_sender: Sender<VideoSetup>,
    setup_code_receiver: Receiver<i32>,
    active: Arc<AtomicBool>,
    supported_formats: VideoFormats,
}

pub const ML_PULL_RENDERER_ERROR: i32 = -100001;

impl VideoDecoder for PullVideoDecoder {
    fn setup(&mut self, setup: VideoSetup) -> i32 {
        if self.setup_sender.send(setup).is_err() {
            return ML_PULL_RENDERER_ERROR;
        }

        match self.setup_code_receiver.recv() {
            Ok(value) => value,
            Err(_) => ML_PULL_RENDERER_ERROR,
        }
    }

    fn start(&mut self) {
        self.active.store(true, Ordering::Release);
    }

    fn stop(&mut self) {
        self.active.store(false, Ordering::Release);
    }

    fn submit_decode_unit(&mut self, _unit: VideoDecodeUnit<&[u8]>) -> DecodeResult {
        unreachable!()
    }

    fn supported_formats(&self) -> VideoFormats {
        self.supported_formats
    }

    fn capabilities(&self) -> VideoCapabilities {
        VideoCapabilities {
            pull_renderer: true,
            ..Default::default()
        }
    }
}

#[derive(Debug, Error)]
pub enum VideoPullResult {
    #[error("no video decode unit present")]
    ValueNotPresent,
    #[error("this video renderer is not active")]
    NotActive,
    #[error("cannot finish the video renderer setup")]
    CannotFinishSetup,
    #[error("the setup success was already sent")]
    SetupSuccessAlreadySent,
}

pub struct PullVideoManager {
    setup_receiver: Receiver<VideoSetup>,
    setup: Option<VideoSetup>,
    setup_code_sender: Option<Sender<i32>>,
    active: Arc<AtomicBool>,
}

impl PullVideoManager {
    pub fn new(supported_formats: VideoFormats) -> (PullVideoDecoder, PullVideoManager) {
        let active = Arc::new(AtomicBool::new(false));

        let (setup_sender, setup_receiver) = channel();
        let (setup_code_sender, setup_code_receiver) = channel();

        (
            PullVideoDecoder {
                active: active.clone(),
                setup_sender,
                setup_code_receiver,
                supported_formats,
            },
            PullVideoManager {
                active,
                setup_receiver,
                setup: None,
                setup_code_sender: Some(setup_code_sender),
            },
        )
    }

    fn check_active(&self) -> Result<(), VideoPullResult> {
        if self.active.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(VideoPullResult::NotActive)
        }
    }

    /// Note: Send setup result must be called after a successful pull
    pub fn poll_setup(&mut self) -> Result<VideoSetup, VideoPullResult> {
        match self.setup_receiver.try_recv() {
            Ok(setup) => {
                self.setup = Some(setup);

                Ok(setup)
            }
            Err(err) => {
                debug!("failed to receive video setup: {err}");
                Err(VideoPullResult::NotActive)
            }
        }
    }
    /// Note: Send setup result must be called after this
    pub fn wait_for_setup(&mut self) -> Result<VideoSetup, VideoPullResult> {
        if let Some(setup) = self.setup.as_ref() {
            return Ok(*setup);
        }

        match self.setup_receiver.recv() {
            Ok(setup) => {
                self.setup = Some(setup);

                Ok(setup)
            }
            Err(err) => {
                debug!("failed to receive video setup: {err}");
                Err(VideoPullResult::NotActive)
            }
        }
    }

    pub fn send_setup_result(&mut self, code: i32) -> Result<(), VideoPullResult> {
        let Some(setup_code_sender) = self.setup_code_sender.take() else {
            return Err(VideoPullResult::SetupSuccessAlreadySent);
        };

        if let Err(err) = setup_code_sender.send(code) {
            self.setup_code_sender = Some(setup_code_sender);

            debug!("failed to send video setup success: {err}");
            return Err(VideoPullResult::CannotFinishSetup);
        }

        Ok(())
    }

    pub fn poll_next_video_frame<'a>(
        &'a mut self,
    ) -> Result<PullVideoDecodeUnit<'a>, VideoPullResult> {
        self.check_active()?;

        unsafe {
            let mut frame_handle: VIDEO_FRAME_HANDLE = null_mut();
            let mut decode_unit: PDECODE_UNIT = null_mut();

            if !LiPollNextVideoFrame(&mut frame_handle, &mut decode_unit) {
                return Err(VideoPullResult::ValueNotPresent);
            }

            Ok(self.handle_next_video_frame(frame_handle, decode_unit))
        }
    }
    pub fn wait_for_next_video_frame<'a>(
        &'a mut self,
    ) -> Result<PullVideoDecodeUnit<'a>, VideoPullResult> {
        self.check_active()?;

        unsafe {
            let mut frame_handle: VIDEO_FRAME_HANDLE = null_mut();
            let mut decode_unit: PDECODE_UNIT = null_mut();

            if !LiWaitForNextVideoFrame(&mut frame_handle, &mut decode_unit) {
                return Err(VideoPullResult::ValueNotPresent);
            }

            Ok(self.handle_next_video_frame(frame_handle, decode_unit))
        }
    }

    /// # Safety
    /// - The PullVideoDecodeUnit will call LiCompleteVideoFrame after it's complete
    /// - No calls to NextVideoFrame are allowed until it is dropped because of &'a mut reference completing the cycle of a video frame
    unsafe fn handle_next_video_frame<'a>(
        &'a mut self,
        frame_handle: VIDEO_FRAME_HANDLE,
        decode_unit: PDECODE_UNIT,
    ) -> PullVideoDecodeUnit<'a> {
        unsafe {
            let decode_unit = convert_decode_unit(decode_unit);

            PullVideoDecodeUnit {
                frame_handle,
                result: DecodeResult::default(),
                decode_unit,
            }
        }
    }
}

pub struct PullVideoDecodeUnit<'a> {
    frame_handle: VIDEO_FRAME_HANDLE,
    decode_unit: VideoDecodeUnit<&'a [u8]>,
    result: DecodeResult,
}

impl<'a> PullVideoDecodeUnit<'a> {
    pub fn set_result(&mut self, result: DecodeResult) {
        self.result = result;
    }
}

impl<'a> Deref for PullVideoDecodeUnit<'a> {
    type Target = VideoDecodeUnit<&'a [u8]>;

    fn deref(&self) -> &Self::Target {
        &self.decode_unit
    }
}

impl<'a> Drop for PullVideoDecodeUnit<'a> {
    fn drop(&mut self) {
        unsafe {
            LiCompleteVideoFrame(self.frame_handle, self.result as i32);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same layout as `CAPABILITY_SLICES_PER_FRAME(x)`: `(unsigned char)x << 24`.
    #[test]
    fn slices_per_frame_goes_to_the_top_byte() {
        assert_eq!(slices_per_frame_capability(4), 4 << 24);
        assert_eq!(slices_per_frame_capability(4) >> 24, 4);
        assert_eq!(slices_per_frame_capability(1000) >> 24, 255);
        assert_eq!(
            slices_per_frame_capability(4) & Capabilities::all().bits(),
            0,
            "must not overlap the capability flags"
        );
    }
}
