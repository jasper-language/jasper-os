//! Native framebuffer and keyboard session integration.
//!
//! Responsibility: bind one firmware framebuffer and the real x86 keyboard to
//! the bounded mechanism in `kernel-core`. It draws a deterministic first frame,
//! renders terminal bytes with a built-in ASCII font and forwards real key
//! transitions to the native terminal session. Its bounded compositor retains
//! only the overlay damage region for partial updates; it does not claim a
//! window system.
//!
//! 原生帧缓冲与键盘会话集成。把固件 framebuffer 和真实 x86 键盘绑定到
//! `kernel-core` 的有界机制，绘制首帧、用内建 ASCII 字体呈现终端字节并把真实
//! 按键送入原生终端会话；compositor 只保留 overlay damage 区域用于局部更新，
//! 不宣称窗口系统已经完成。

use alloc::vec::Vec;
#[cfg(target_arch = "x86_64")]
use bootloader_api::info::{FrameBuffer, PixelFormat};
use kernel_core::display_compositor::{Compositor, DamageRect, LayerKey, LayerPixels, LayerSpec};
use kernel_core::display_input::{
    plan_key_queue_capacity, DisplayBackend, DisplayCapabilities, DisplayInputError,
    DynamicDisplayInputSession, KeyInput, PixelLayout, SurfaceSpec,
};

use crate::sync::IrqSpinLock;
use crate::{kprintln, mm};

const TEXT_COLUMNS: usize = 96;
const TEXT_ROWS: usize = 32;
const TEXT_CELLS: usize = TEXT_COLUMNS * TEXT_ROWS;
const OVERLAY_WIDTH: u32 = 16;
const OVERLAY_HEIGHT: u32 = 8;
const OVERLAY_BYTES: usize = OVERLAY_WIDTH as usize * OVERLAY_HEIGHT as usize * 4;
const OVERLAY_SURFACE: SurfaceSpec = SurfaceSpec {
    width: OVERLAY_WIDTH,
    height: OVERLAY_HEIGHT,
    stride: OVERLAY_WIDTH,
    bytes_per_pixel: 4,
    layout: PixelLayout::Bgr,
};
const ACCENT_WIDTH: u32 = 16;
const ACCENT_HEIGHT: u32 = 8;
const ACCENT_BYTES: usize = ACCENT_WIDTH as usize * ACCENT_HEIGHT as usize * 4;
const ACCENT_SURFACE: SurfaceSpec = SurfaceSpec {
    width: ACCENT_WIDTH,
    height: ACCENT_HEIGHT,
    stride: ACCENT_WIDTH,
    bytes_per_pixel: 4,
    layout: PixelLayout::Bgr,
};
struct Runtime {
    base: usize,
    len: usize,
    surface: SurfaceSpec,
    session: DynamicDisplayInputSession,
    compositor: Compositor<3>,
    overlay: [u8; OVERLAY_BYTES],
    overlay_key: LayerKey,
    accent: [u8; ACCENT_BYTES],
    accent_key: Option<LayerKey>,
    overlay_damage: DamageRect,
    overlay_region_len: usize,
    overlay_base: Vec<u8>,
    ui_surface: Option<SurfaceSpec>,
    ui_key: Option<LayerKey>,
    ui_pixels: Vec<u8>,
    ui2_surface: Option<SurfaceSpec>,
    ui2_key: Option<LayerKey>,
    ui2_pixels: Vec<u8>,
    pressed: u32,
    released: u32,
    text: [u8; TEXT_CELLS],
    cursor: usize,
    prompt_reported: bool,
    echo_reported: bool,
    ui_input_capture: bool,
}

static DISPLAY: IrqSpinLock<Option<Runtime>> = IrqSpinLock::ranked(crate::lockorder::DISPLAY, None);

struct Prepared {
    base: usize,
    len: usize,
    surface: SurfaceSpec,
}

static PREPARED: IrqSpinLock<Option<Prepared>> =
    IrqSpinLock::ranked(crate::lockorder::DISPLAY, None);

/// Bind and immediately paint one boot frame from the firmware framebuffer.
///
/// 绑定固件帧缓冲并立即绘制一帧启动画面。
#[cfg(target_arch = "x86_64")]
pub fn prepare(framebuffer: FrameBuffer) -> Result<(), DisplayInputError> {
    let info = framebuffer.info();
    let layout = match info.pixel_format {
        PixelFormat::Rgb => PixelLayout::Rgb,
        PixelFormat::Bgr => PixelLayout::Bgr,
        PixelFormat::U8 => PixelLayout::Gray,
        _ => return Err(DisplayInputError::Unsupported),
    };
    let width = u32::try_from(info.width).map_err(|_| DisplayInputError::InvalidSurface)?;
    let height = u32::try_from(info.height).map_err(|_| DisplayInputError::InvalidSurface)?;
    let stride = u32::try_from(info.stride).map_err(|_| DisplayInputError::InvalidSurface)?;
    let bytes_per_pixel =
        u8::try_from(info.bytes_per_pixel).map_err(|_| DisplayInputError::InvalidSurface)?;
    let surface = SurfaceSpec {
        width,
        height,
        stride,
        bytes_per_pixel,
        layout,
    };
    let required = surface.validate()?;
    if required > info.byte_len as u64 {
        return Err(DisplayInputError::InvalidSurface);
    }
    let buffer = framebuffer.into_buffer();
    *PREPARED.lock() = Some(Prepared {
        base: buffer.as_mut_ptr() as usize,
        len: buffer.len(),
        surface,
    });
    Ok(())
}

/// Start the native display runtime after the kernel heap is available.
pub fn start() -> Result<(), DisplayInputError> {
    let prepared = PREPARED
        .lock()
        .take()
        .ok_or(DisplayInputError::Unsupported)?;
    let surface = prepared.surface;
    let required = surface.validate()?;
    #[cfg(target_arch = "x86_64")]
    let keyboard = crate::arch::x86_64::keyboard::init(); // JASPER-ISA-REFERENCE: x86_64 input backend.
    #[cfg(not(target_arch = "x86_64"))]
    let keyboard = false;
    let input_capacity =
        plan_key_queue_capacity(required, mm::heap::limit()).ok_or(DisplayInputError::Failed)?;
    let session = DynamicDisplayInputSession::open(
        DisplayCapabilities {
            backend: Some(DisplayBackend::Framebuffer),
            surface: Some(surface),
            keyboard,
        },
        input_capacity,
    )?;
    let mut compositor = Compositor::<3>::new();
    let overlay_key = compositor
        .create(LayerSpec {
            surface: OVERLAY_SURFACE,
            x: surface.width.saturating_sub(24) as i32,
            y: 22,
            z_order: 10,
            visible: true,
            opacity: 0xff,
        })
        .map_err(|_| DisplayInputError::Failed)?;
    let accent_key = compositor
        .create(LayerSpec {
            surface: ACCENT_SURFACE,
            x: surface.width.saturating_sub(32) as i32,
            y: 22,
            z_order: 20,
            visible: true,
            opacity: 0xa0,
        })
        .map_err(|_| DisplayInputError::Failed)?;
    let mut overlay = [0u8; OVERLAY_BYTES];
    fill_surface(&mut overlay, (0x29, 0xd3, 0xb6));
    let mut accent = [0u8; ACCENT_BYTES];
    fill_surface(&mut accent, (0x12, 0x36, 0x4a));
    let overlay_damage = DamageRect::for_layer(
        compositor
            .snapshot(overlay_key)
            .map_err(|_| DisplayInputError::Failed)?
            .layer,
        surface,
    )
    .map_err(|_| DisplayInputError::Failed)?
    .union(
        DamageRect::for_layer(
            compositor
                .snapshot(accent_key)
                .map_err(|_| DisplayInputError::Failed)?
                .layer,
            surface,
        )
        .map_err(|_| DisplayInputError::Failed)?,
    );
    let overlay_region_len = region_bytes(overlay_damage, surface)?;
    let frame_len = usize::try_from(required).map_err(|_| DisplayInputError::InvalidSurface)?;
    if prepared.len < frame_len {
        return Err(DisplayInputError::InvalidSurface);
    }
    let mut runtime = Runtime {
        base: prepared.base,
        len: frame_len,
        surface,
        session,
        compositor,
        overlay,
        overlay_key,
        accent,
        accent_key: Some(accent_key),
        overlay_damage,
        overlay_region_len,
        overlay_base: alloc::vec![0u8; overlay_region_len],
        ui_surface: None,
        ui_key: None,
        ui_pixels: Vec::new(),
        ui2_surface: None,
        ui2_key: None,
        ui2_pixels: Vec::new(),
        pressed: 0,
        released: 0,
        text: [b' '; TEXT_CELLS],
        cursor: 0,
        prompt_reported: false,
        echo_reported: false,
        ui_input_capture: false,
    };
    runtime.append_text(b"JASPER-OS NATIVE TERMINAL\n\n");
    runtime.paint_boot_frame()?;
    kprintln!(
        "[JSR-DISPLAY-COMPOSITOR] layers=2 visible=2 primary=terminal overlays=bounded alpha=true full_frame=false damage=true overlay_damage=true text_full=true input_capacity={}",
        input_capacity
    );
    *DISPLAY.lock() = Some(runtime);
    Ok(())
}

/// Poll the real keyboard into the bounded session and update the visible state.
///
/// 轮询真实键盘并写入有界会话，同时更新可见状态。
pub fn poll_input() -> usize {
    let mut count = 0;
    for _ in 0..32 {
        let Some(key) = crate::arch::try_read_input_event() else {
            break;
        };
        let mut guard = DISPLAY.lock();
        let Some(runtime) = guard.as_mut() else {
            break;
        };
        if runtime.session.push_key(key).is_err() {
            break;
        }
        if key.pressed {
            runtime.pressed = runtime.pressed.saturating_add(1);
        } else {
            runtime.released = runtime.released.saturating_add(1);
        }
        runtime.paint_input_indicator();
        count += 1;
    }
    if count != 0 {
        report();
    }
    count
}

/// Remove one key transition for a terminal frontend.
///
/// 为终端前端取出一次按键状态变化。
pub fn next_key() -> Option<KeyInput> {
    DISPLAY.lock().as_mut().and_then(|runtime| {
        if runtime.ui_input_capture {
            None
        } else {
            runtime.session.pop_key().ok()
        }
    })
}

/// Route queued native key transitions to the UI host instead of the terminal.
///
/// 把原生按键队列路由给 UI 宿主而不是终端；没有真实键盘时失败关闭。
pub fn begin_ui_input_capture() -> bool {
    let mut guard = DISPLAY.lock();
    let Some(runtime) = guard.as_mut() else {
        return false;
    };
    if !runtime.session.keyboard_available() {
        return false;
    }
    runtime.ui_input_capture = true;
    true
}

/// Return terminal input routing after the bounded UI input transaction.
pub fn end_ui_input_capture() {
    if let Some(runtime) = DISPLAY.lock().as_mut() {
        runtime.ui_input_capture = false;
    }
}

/// Remove one native key transition for the active UI input owner.
pub fn next_ui_key() -> Option<KeyInput> {
    DISPLAY.lock().as_mut().and_then(|runtime| {
        if runtime.ui_input_capture {
            runtime.session.pop_key().ok()
        } else {
            None
        }
    })
}

/// Render bytes emitted by the native terminal into the framebuffer text view.
///
/// 将原生终端输出绘制到 framebuffer 文本视图；无显示后端时安全忽略。
pub fn terminal_write(bytes: &[u8]) {
    let mut guard = DISPLAY.lock();
    let Some(runtime) = guard.as_mut() else {
        return;
    };
    runtime.append_text(bytes);
    let _ = runtime.paint_text_frame();
}

/// Report the real backend state without holding the display lock across output.
///
/// 不跨输出持有显示锁地报告真实后端状态。
pub fn report() {
    let snapshot = DISPLAY.lock().as_ref().map(|runtime| {
        (
            runtime.surface,
            runtime.session.keyboard_available(),
            runtime.session.frames(),
            runtime.session.pending_keys(),
            runtime.session.key_capacity(),
            runtime.session.dropped_keys(),
            runtime.compositor.count(),
            runtime.pressed,
            runtime.released,
        )
    });
    if let Some((surface, keyboard, frames, keys, capacity, dropped, layers, pressed, released)) =
        snapshot
    {
        kprintln!(
            "[JSR-DISPLAY] backend=framebuffer keyboard={} width={} height={} stride={} bpp={} frames={} keys={} input_capacity={} dropped={} compositor_layers={} pressed={} released={}",
            keyboard,
            surface.width,
            surface.height,
            surface.stride,
            surface.bytes_per_pixel,
            frames,
            keys,
            capacity,
            dropped,
            layers,
            pressed,
            released
        );
    } else {
        kprintln!("[JSR-DISPLAY] backend=none keyboard=unavailable");
    }
}

/// Primary surface dimensions discovered from the firmware framebuffer.
///
/// 从固件帧缓冲发现主显示面的真实尺寸；没有显示后端时返回 `None`。
pub fn primary_surface() -> Option<(u32, u32)> {
    DISPLAY
        .lock()
        .as_ref()
        .map(|runtime| (runtime.surface.width, runtime.surface.height))
}

/// Current display/keyboard facts for UI capability-event construction.
pub fn ui_capability_facts() -> Option<(SurfaceSpec, bool)> {
    DISPLAY
        .lock()
        .as_ref()
        .map(|runtime| (runtime.surface, runtime.session.keyboard_available()))
}

/// Register one Engine-produced Surface as a native compositor layer, then
/// present the updated framebuffer. Returns the layer's top-left position.
///
/// 把 Engine 生成的 Surface 注册为原生 compositor 图层并提交新帧，返回图层左上角坐标。
pub fn present_ui_frame(
    source: SurfaceSpec,
    pixels: &[u8],
) -> Result<(u32, u32), DisplayInputError> {
    let expected = source.validate()?;
    if expected != pixels.len() as u64 {
        return Err(DisplayInputError::InvalidFrame);
    }
    let mut owned_pixels = Vec::new();
    owned_pixels
        .try_reserve_exact(pixels.len())
        .map_err(|_| DisplayInputError::Failed)?;
    owned_pixels.extend_from_slice(pixels);
    let (region_len, same_surface) = {
        let guard = DISPLAY.lock();
        let runtime = guard.as_ref().ok_or(DisplayInputError::Unsupported)?;
        (
            runtime.ui_overlay_region_len(source)?,
            runtime.ui_surface == Some(source),
        )
    };
    let mut overlay_base = if same_surface {
        None
    } else {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(region_len)
            .map_err(|_| DisplayInputError::Failed)?;
        bytes.resize(region_len, 0);
        Some(bytes)
    };
    let mut owned_pixels = Some(owned_pixels);
    let (result, retired) = {
        let mut guard = DISPLAY.lock();
        guard.as_mut().map_or_else(
            || (Err(DisplayInputError::Unsupported), (Vec::new(), Vec::new())),
            |runtime| {
                let (result, retired) = match runtime.adopt_ui_frame(
                    source,
                    &mut owned_pixels,
                    &mut overlay_base,
                    region_len,
                ) {
                    Ok((x, y, retired)) => {
                        let position = (x, y);
                        let result = runtime
                            .paint_text_frame()
                            .map(|()| position)
                            .map_err(|_| DisplayInputError::Failed);
                        if result.is_ok() {
                            kprintln!(
                                "[JSR-DISPLAY-UI] presented=true width={} height={} x={} y={} layers={}",
                                source.width,
                                source.height,
                                position.0,
                                position.1,
                                runtime.compositor.count()
                            );
                        }
                        (result, retired)
                    }
                    Err(error) => (Err(error), (Vec::new(), Vec::new())),
                };
                (result, retired)
            },
        )
    };
    drop(owned_pixels);
    drop(overlay_base);
    drop(retired);
    result
}

/// Present two Engine Surfaces as independent native compositor layers.
///
/// This is the bounded two-window framebuffer path: the decorative accent layer
/// is retired so the existing three-layer compositor holds the overlay plus two
/// application Surfaces. Both frames are validated and copied before the display
/// transaction begins.
pub fn present_ui_layers(
    frames: [(SurfaceSpec, &[u8]); 2],
) -> Result<[(u32, u32); 2], DisplayInputError> {
    for (source, pixels) in frames {
        if source.validate()? != pixels.len() as u64 {
            return Err(DisplayInputError::InvalidFrame);
        }
    }
    let mut owned = [Vec::new(), Vec::new()];
    for (index, (_, pixels)) in frames.iter().enumerate() {
        owned[index]
            .try_reserve_exact(pixels.len())
            .map_err(|_| DisplayInputError::Failed)?;
        owned[index].extend_from_slice(pixels);
    }
    let sources = [frames[0].0, frames[1].0];
    let (positions, damage, region_len) = {
        let guard = DISPLAY.lock();
        let runtime = guard.as_ref().ok_or(DisplayInputError::Unsupported)?;
        let (positions, damage) = runtime.ui_pair_layout(sources)?;
        (positions, damage, region_bytes(damage, runtime.surface)?)
    };
    let mut overlay_base = Vec::new();
    overlay_base
        .try_reserve_exact(region_len)
        .map_err(|_| DisplayInputError::Failed)?;
    overlay_base.resize(region_len, 0);
    let mut owned = owned.map(Some);
    let (result, retired) = {
        let mut guard = DISPLAY.lock();
        guard.as_mut().map_or_else(
            || {
                (
                    Err(DisplayInputError::Unsupported),
                    (Vec::new(), Vec::new(), Vec::new()),
                )
            },
            |runtime| {
                let result = runtime
                    .adopt_ui_layers(
                        sources,
                        positions,
                        &mut owned,
                        overlay_base,
                        damage,
                        region_len,
                    )
                    .and_then(|retired| {
                        runtime.paint_text_frame()?;
                        Ok(retired)
                    });
                match result {
                    Ok(retired) => {
                        kprintln!(
                            "[JSR-DISPLAY-UI] presented_layers=2 width0={} height0={} x0={} y0={} x1={} y1={} layers={}",
                            sources[0].width,
                            sources[0].height,
                            positions[0].0,
                            positions[0].1,
                            positions[1].0,
                            positions[1].1,
                            runtime.compositor.count()
                        );
                        (Ok(positions), retired)
                    }
                    Err(error) => (Err(error), (Vec::new(), Vec::new(), Vec::new())),
                }
            },
        )
    };
    drop(owned);
    drop(retired);
    result
}

/// Read one already-presented native framebuffer pixel as RGB.
///
/// 把已经提交的 framebuffer 像素读取为 RGB。
pub fn read_pixel_rgb(x: u32, y: u32) -> Option<(u8, u8, u8)> {
    DISPLAY
        .lock()
        .as_ref()
        .and_then(|runtime| runtime.read_pixel(x, y))
}

impl Runtime {
    fn ui_overlay_region_len(&self, source: SurfaceSpec) -> Result<usize, DisplayInputError> {
        let (_, _, damage) = self.ui_layout(source)?;
        region_bytes(damage, self.surface)
    }

    fn ui_layout(&self, source: SurfaceSpec) -> Result<(u32, u32, DamageRect), DisplayInputError> {
        let x = self.surface.width.saturating_sub(source.width) / 2;
        let y = self.surface.height.saturating_sub(source.height) / 2;
        let layer = LayerSpec {
            surface: source,
            x: x as i32,
            y: y as i32,
            z_order: 5,
            visible: true,
            opacity: 0xff,
        };
        let ui_damage =
            DamageRect::for_layer(layer, self.surface).map_err(|_| DisplayInputError::Failed)?;
        Ok((x, y, self.overlay_damage.union(ui_damage)))
    }

    fn ui_pair_layout(
        &self,
        sources: [SurfaceSpec; 2],
    ) -> Result<([(u32, u32); 2], DamageRect), DisplayInputError> {
        let gap = 4u32;
        let total_width = sources[0]
            .width
            .checked_add(gap)
            .and_then(|width| width.checked_add(sources[1].width))
            .ok_or(DisplayInputError::InvalidSurface)?;
        let start_x = self.surface.width.saturating_sub(total_width) / 2;
        let x0 = start_x;
        let x1 = start_x
            .checked_add(sources[0].width)
            .and_then(|x| x.checked_add(gap))
            .ok_or(DisplayInputError::InvalidSurface)?;
        let y0 = self.surface.height.saturating_sub(sources[0].height) / 2;
        let y1 = self.surface.height.saturating_sub(sources[1].height) / 2;
        let first = DamageRect::for_layer(
            LayerSpec {
                surface: sources[0],
                x: x0 as i32,
                y: y0 as i32,
                z_order: 5,
                visible: true,
                opacity: 0xff,
            },
            self.surface,
        )
        .map_err(|_| DisplayInputError::Failed)?;
        let second = DamageRect::for_layer(
            LayerSpec {
                surface: sources[1],
                x: x1 as i32,
                y: y1 as i32,
                z_order: 6,
                visible: true,
                opacity: 0xff,
            },
            self.surface,
        )
        .map_err(|_| DisplayInputError::Failed)?;
        Ok((
            [(x0, y0), (x1, y1)],
            self.overlay_damage.union(first).union(second),
        ))
    }

    fn adopt_ui_layers(
        &mut self,
        sources: [SurfaceSpec; 2],
        positions: [(u32, u32); 2],
        pixels: &mut [Option<Vec<u8>>; 2],
        overlay_base: Vec<u8>,
        damage: DamageRect,
        region_len: usize,
    ) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), DisplayInputError> {
        if let Some(key) = self.accent_key.take() {
            self.compositor
                .destroy(key)
                .map_err(|_| DisplayInputError::Failed)?;
        }
        for key in [self.ui_key.take(), self.ui2_key.take()]
            .into_iter()
            .flatten()
        {
            self.compositor
                .destroy(key)
                .map_err(|_| DisplayInputError::Failed)?;
        }
        let first = self
            .compositor
            .create(LayerSpec {
                surface: sources[0],
                x: positions[0].0 as i32,
                y: positions[0].1 as i32,
                z_order: 5,
                visible: true,
                opacity: 0xff,
            })
            .map_err(|_| DisplayInputError::Failed)?;
        let second = self
            .compositor
            .create(LayerSpec {
                surface: sources[1],
                x: positions[1].0 as i32,
                y: positions[1].1 as i32,
                z_order: 6,
                visible: true,
                opacity: 0xff,
            })
            .map_err(|_| DisplayInputError::Failed)?;
        let first_pixels = core::mem::replace(
            &mut self.ui_pixels,
            pixels[0].take().ok_or(DisplayInputError::InvalidFrame)?,
        );
        let second_pixels = core::mem::replace(
            &mut self.ui2_pixels,
            pixels[1].take().ok_or(DisplayInputError::InvalidFrame)?,
        );
        let old_base = core::mem::replace(&mut self.overlay_base, overlay_base);
        self.ui_surface = Some(sources[0]);
        self.ui2_surface = Some(sources[1]);
        self.ui_key = Some(first);
        self.ui2_key = Some(second);
        self.overlay_damage = damage;
        self.overlay_region_len = region_len;
        Ok((first_pixels, second_pixels, old_base))
    }

    fn adopt_ui_frame(
        &mut self,
        source: SurfaceSpec,
        pixels: &mut Option<Vec<u8>>,
        overlay_base: &mut Option<Vec<u8>>,
        region_len: usize,
    ) -> Result<(u32, u32, (Vec<u8>, Vec<u8>)), DisplayInputError> {
        if let Some(key) = self.ui2_key.take() {
            self.compositor
                .destroy(key)
                .map_err(|_| DisplayInputError::Failed)?;
            self.ui2_surface = None;
            self.ui2_pixels.clear();
        }
        let (x, y, damage) = self.ui_layout(source)?;
        if pixels.as_ref().is_none()
            || overlay_base
                .as_ref()
                .is_some_and(|bytes| bytes.len() != region_len)
        {
            return Err(DisplayInputError::InvalidFrame);
        }
        if self.ui_surface != Some(source) {
            if let Some(key) = self.ui_key.take() {
                self.compositor
                    .destroy(key)
                    .map_err(|_| DisplayInputError::Failed)?;
            }
            let key = self
                .compositor
                .create(LayerSpec {
                    surface: source,
                    x: x as i32,
                    y: y as i32,
                    z_order: 5,
                    visible: true,
                    opacity: 0xff,
                })
                .map_err(|_| DisplayInputError::Failed)?;
            self.ui_surface = Some(source);
            self.ui_key = Some(key);
            let old_pixels = core::mem::replace(
                &mut self.ui_pixels,
                pixels.take().ok_or(DisplayInputError::InvalidFrame)?,
            );
            let old_base = core::mem::replace(
                &mut self.overlay_base,
                overlay_base.take().ok_or(DisplayInputError::InvalidFrame)?,
            );
            self.overlay_damage = damage;
            self.overlay_region_len = region_len;
            Ok((x, y, (old_pixels, old_base)))
        } else {
            let old_pixels = core::mem::replace(
                &mut self.ui_pixels,
                pixels.take().ok_or(DisplayInputError::InvalidFrame)?,
            );
            if let Some(key) = self.ui_key {
                self.compositor
                    .set_position(key, x as i32, y as i32)
                    .map_err(|_| DisplayInputError::Failed)?;
            }
            Ok((x, y, (old_pixels, Vec::new())))
        }
    }

    fn read_pixel(&self, x: u32, y: u32) -> Option<(u8, u8, u8)> {
        if x >= self.surface.width || y >= self.surface.height {
            return None;
        }
        let bpp = usize::from(self.surface.bytes_per_pixel);
        let offset = (y as usize)
            .checked_mul(self.surface.stride as usize)?
            .checked_add(x as usize)?
            .checked_mul(bpp)?;
        if offset.checked_add(bpp)? > self.len {
            return None;
        }
        // SAFETY: the framebuffer remains mapped for the Runtime lifetime and
        // the offset was checked against its exact presented length.
        let pixel = unsafe { core::slice::from_raw_parts(self.base as *const u8, self.len) };
        match self.surface.layout {
            PixelLayout::Rgb | PixelLayout::Rgba => {
                Some((pixel[offset], pixel[offset + 1], pixel[offset + 2]))
            }
            PixelLayout::Bgr => Some((pixel[offset + 2], pixel[offset + 1], pixel[offset])),
            PixelLayout::Gray => Some((pixel[offset], pixel[offset], pixel[offset])),
        }
    }

    fn paint_boot_frame(&mut self) -> Result<(), DisplayInputError> {
        let required = usize::try_from(self.required_bytes()?)
            .map_err(|_| DisplayInputError::InvalidSurface)?;
        if self.len < required {
            return Err(DisplayInputError::InvalidSurface);
        }
        self.fill(0x0f, 0x17, 0x20);
        self.rect(0, 0, self.surface.width, 8, 0x29, 0xd3, 0xb6);
        self.rect(0, 8, self.surface.width, 2, 0x12, 0x36, 0x4a);
        let margin = self.surface.width / 12;
        let panel = self.surface.width / 4;
        let top = self.surface.height / 4;
        let height = self.surface.height / 3;
        self.rect(margin, top, panel, height, 0x17, 0x2a, 0x3c);
        self.rect(
            margin + panel + margin,
            top,
            panel,
            height,
            0x1c,
            0x35,
            0x4b,
        );
        self.rect(
            margin + 2 * (panel + margin),
            top,
            panel,
            height,
            0x20,
            0x40,
            0x59,
        );
        self.paint_text();
        self.snapshot_overlay_base()?;
        self.compose_overlay()?;
        let ticket = self.session.prepare_frame(self.required_bytes()?)?;
        self.session.commit_frame(ticket)?;
        Ok(())
    }

    fn paint_text_frame(&mut self) -> Result<(), DisplayInputError> {
        self.fill(0x08, 0x11, 0x18);
        self.rect(0, 0, self.surface.width, 6, 0x29, 0xd3, 0xb6);
        self.paint_text();
        self.snapshot_overlay_base()?;
        self.compose_overlay()?;
        let ticket = self.session.prepare_frame(self.required_bytes()?)?;
        self.session.commit_frame(ticket)?;
        Ok(())
    }

    fn append_text(&mut self, bytes: &[u8]) {
        for byte in bytes.iter().copied() {
            match byte {
                b'\r' => self.cursor -= self.cursor % TEXT_COLUMNS,
                b'\n' => self.newline(),
                0x08 => {
                    if self.cursor % TEXT_COLUMNS != 0 {
                        self.cursor -= 1;
                        self.text[self.cursor] = b' ';
                    }
                }
                0x20..=0x7e => {
                    if self.cursor >= TEXT_CELLS {
                        self.newline();
                    }
                    self.text[self.cursor] = byte.to_ascii_uppercase();
                    self.cursor += 1;
                    if self.cursor % TEXT_COLUMNS == 0 {
                        self.newline();
                    }
                }
                _ => {}
            }
        }
        if !self.prompt_reported && self.contains_text(b"JASPER> ") {
            self.prompt_reported = true;
            kprintln!("[JSR-GTERM] prompt=visible");
        }
        if !self.echo_reported && self.contains_text(b"NATIVE-ECHO-OK") {
            self.echo_reported = true;
            kprintln!("[JSR-GTERM] output=echo-ok visible=true");
        }
    }

    fn newline(&mut self) {
        let row = self.cursor / TEXT_COLUMNS;
        if self.cursor >= TEXT_CELLS || row + 1 >= TEXT_ROWS {
            self.text.copy_within(TEXT_COLUMNS.., 0);
            self.text[TEXT_CELLS - TEXT_COLUMNS..].fill(b' ');
            self.cursor = TEXT_CELLS - TEXT_COLUMNS;
        } else {
            self.cursor = (row + 1) * TEXT_COLUMNS;
        }
    }

    fn contains_text(&self, needle: &[u8]) -> bool {
        if needle.is_empty() || needle.len() > TEXT_CELLS {
            return false;
        }
        self.text
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn paint_text(&mut self) {
        let origin_x = 16u32;
        let origin_y = 16u32;
        let cell_width = 12u32;
        let cell_height = 20u32;
        for row in 0..TEXT_ROWS {
            for column in 0..TEXT_COLUMNS {
                let character = self.text[row * TEXT_COLUMNS + column];
                if character == b' ' || character == 0 {
                    continue;
                }
                let glyph = glyph(character);
                for (glyph_row, bits) in glyph.iter().copied().enumerate() {
                    for glyph_column in 0..5u32 {
                        if bits & (1u8 << (4 - glyph_column as u8)) == 0 {
                            continue;
                        }
                        let x = origin_x + column as u32 * cell_width + glyph_column * 2;
                        let y = origin_y + row as u32 * cell_height + glyph_row as u32 * 2;
                        self.rect(x, y, 2, 2, 0xd8, 0xf3, 0xea);
                    }
                }
            }
        }
    }

    fn paint_input_indicator(&mut self) {
        let color = if self.pressed.wrapping_sub(self.released) & 1 == 0 {
            (0x29, 0xd3, 0xb6)
        } else {
            (0xf4, 0xb8, 0x42)
        };
        fill_surface(&mut self.overlay, color);
        let accent = if self.pressed.wrapping_sub(self.released) & 1 == 0 {
            (0x12, 0x36, 0x4a)
        } else {
            (0x54, 0x2c, 0x18)
        };
        fill_surface(&mut self.accent, accent);
        let _ = self.compose_overlay();
        if let Ok(bytes) = self.required_bytes() {
            if let Ok(ticket) = self.session.prepare_frame(bytes) {
                let _ = self.session.commit_frame(ticket);
            }
        }
    }

    fn required_bytes(&self) -> Result<u64, DisplayInputError> {
        self.surface.validate()
    }

    fn snapshot_overlay_base(&mut self) -> Result<(), DisplayInputError> {
        let damage = self.overlay_damage;
        let bpp = usize::from(self.surface.bytes_per_pixel);
        let row_bytes = usize::try_from(damage.width)
            .map_err(|_| DisplayInputError::InvalidSurface)?
            .checked_mul(bpp)
            .ok_or(DisplayInputError::InvalidSurface)?;
        let bottom = i64::from(damage.y) + i64::from(damage.height);
        // SAFETY: the framebuffer pointer and length remain valid for the
        // lifetime of this Runtime; damage was clipped during initialization.
        let frame = unsafe { core::slice::from_raw_parts(self.base as *const u8, self.len) };
        for (source_row, y) in (i64::from(damage.y)..bottom).enumerate() {
            let source_offset = usize::try_from(
                y.checked_mul(i64::from(self.surface.stride))
                    .and_then(|row| row.checked_add(i64::from(damage.x)))
                    .and_then(|pixel| pixel.checked_mul(i64::from(self.surface.bytes_per_pixel)))
                    .ok_or(DisplayInputError::InvalidSurface)?,
            )
            .map_err(|_| DisplayInputError::InvalidSurface)?;
            let source_end = source_offset
                .checked_add(row_bytes)
                .ok_or(DisplayInputError::InvalidSurface)?;
            let destination_start = source_row
                .checked_mul(row_bytes)
                .ok_or(DisplayInputError::InvalidSurface)?;
            let destination_end = destination_start
                .checked_add(row_bytes)
                .ok_or(DisplayInputError::InvalidSurface)?;
            self.overlay_base[destination_start..destination_end]
                .copy_from_slice(&frame[source_offset..source_end]);
        }
        Ok(())
    }

    fn compose_overlay(&self) -> Result<(), DisplayInputError> {
        let mut layers = [
            LayerPixels {
                key: self.overlay_key,
                bytes: &self.overlay,
            },
            LayerPixels {
                key: self.overlay_key,
                bytes: &[],
            },
            LayerPixels {
                key: self.overlay_key,
                bytes: &[],
            },
        ];
        let mut layer_count = 1;
        if let Some(key) = self.accent_key {
            layers[layer_count] = LayerPixels {
                key,
                bytes: &self.accent,
            };
            layer_count += 1;
        }
        if let Some(key) = self.ui_key {
            layers[layer_count] = LayerPixels {
                key,
                bytes: &self.ui_pixels,
            };
            layer_count += 1;
        }
        if let Some(key) = self.ui2_key {
            if layer_count >= layers.len() {
                return Err(DisplayInputError::Failed);
            }
            layers[layer_count] = LayerPixels {
                key,
                bytes: &self.ui2_pixels,
            };
            layer_count += 1;
        }
        // SAFETY: the framebuffer pointer and length remain valid for the
        // lifetime of this Runtime, and all geometry is validated before write.
        let frame = unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.len) };
        self.compositor
            .compose_retained_region(
                self.surface,
                frame,
                &self.overlay_base[..self.overlay_region_len],
                &layers[..layer_count],
                self.overlay_damage,
            )
            .map(|_| ())
            .map_err(|_| DisplayInputError::Failed)
    }

    fn fill(&mut self, red: u8, green: u8, blue: u8) {
        let width = self.surface.width as usize;
        let height = self.surface.height as usize;
        self.rect(0, 0, width as u32, height as u32, red, green, blue);
    }

    fn rect(&mut self, x: u32, y: u32, width: u32, height: u32, red: u8, green: u8, blue: u8) {
        let right = x.saturating_add(width).min(self.surface.width);
        let bottom = y.saturating_add(height).min(self.surface.height);
        for row in y..bottom {
            for column in x..right {
                self.pixel(column, row, red, green, blue);
            }
        }
    }

    fn pixel(&mut self, x: u32, y: u32, red: u8, green: u8, blue: u8) {
        let bpp = self.surface.bytes_per_pixel as usize;
        let offset = (y as usize * self.surface.stride as usize + x as usize).saturating_mul(bpp);
        if offset + bpp > self.len {
            return;
        }
        // SAFETY: geometry was validated against the owned framebuffer length.
        unsafe {
            let pointer = self.base as *mut u8;
            match self.surface.layout {
                PixelLayout::Rgb | PixelLayout::Bgr | PixelLayout::Rgba => {
                    let (first, third) = match self.surface.layout {
                        PixelLayout::Rgb | PixelLayout::Rgba => (red, blue),
                        PixelLayout::Bgr => (blue, red),
                        PixelLayout::Gray => unreachable!(),
                    };
                    core::ptr::write_volatile(pointer.add(offset), first);
                    core::ptr::write_volatile(pointer.add(offset + 1), green);
                    core::ptr::write_volatile(pointer.add(offset + 2), third);
                    for padding in 3..bpp {
                        core::ptr::write_volatile(pointer.add(offset + padding), 0xff);
                    }
                }
                PixelLayout::Gray => {
                    let gray = ((u16::from(red) + u16::from(green) + u16::from(blue)) / 3) as u8;
                    core::ptr::write_volatile(pointer.add(offset), gray);
                }
            }
        }
    }
}

fn region_bytes(damage: DamageRect, surface: SurfaceSpec) -> Result<usize, DisplayInputError> {
    let pixels = usize::try_from(damage.width)
        .map_err(|_| DisplayInputError::InvalidSurface)?
        .checked_mul(usize::try_from(damage.height).map_err(|_| DisplayInputError::InvalidSurface)?)
        .ok_or(DisplayInputError::InvalidSurface)?;
    pixels
        .checked_mul(usize::from(surface.bytes_per_pixel))
        .ok_or(DisplayInputError::InvalidSurface)
}

fn fill_surface(bytes: &mut [u8], color: (u8, u8, u8)) {
    for pixel in bytes.chunks_exact_mut(4) {
        pixel.copy_from_slice(&[color.2, color.1, color.0, 0xff]);
    }
}

/// Minimal 5x7 glyph set for the native text frontend.
///
/// 原生文本前端使用的最小 5x7 字形集；未知字符绘制为问号。
pub(crate) fn glyph(character: u8) -> [u8; 7] {
    match character.to_ascii_uppercase() {
        b'A' => [0x0e, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'B' => [0x1e, 0x11, 0x11, 0x1e, 0x11, 0x11, 0x1e],
        b'C' => [0x0f, 0x10, 0x10, 0x10, 0x10, 0x10, 0x0f],
        b'D' => [0x1e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x1e],
        b'E' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x1f],
        b'F' => [0x1f, 0x10, 0x10, 0x1e, 0x10, 0x10, 0x10],
        b'G' => [0x0f, 0x10, 0x10, 0x13, 0x11, 0x11, 0x0f],
        b'H' => [0x11, 0x11, 0x11, 0x1f, 0x11, 0x11, 0x11],
        b'I' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x1f],
        b'J' => [0x01, 0x01, 0x01, 0x01, 0x11, 0x11, 0x0e],
        b'K' => [0x11, 0x12, 0x14, 0x18, 0x14, 0x12, 0x11],
        b'L' => [0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x1f],
        b'M' => [0x11, 0x1b, 0x15, 0x15, 0x11, 0x11, 0x11],
        b'N' => [0x11, 0x19, 0x15, 0x13, 0x11, 0x11, 0x11],
        b'O' => [0x0e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'P' => [0x1e, 0x11, 0x11, 0x1e, 0x10, 0x10, 0x10],
        b'Q' => [0x0e, 0x11, 0x11, 0x11, 0x15, 0x12, 0x0d],
        b'R' => [0x1e, 0x11, 0x11, 0x1e, 0x14, 0x12, 0x11],
        b'S' => [0x0f, 0x10, 0x10, 0x0e, 0x01, 0x01, 0x1e],
        b'T' => [0x1f, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04],
        b'U' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x0e],
        b'V' => [0x11, 0x11, 0x11, 0x11, 0x11, 0x0a, 0x04],
        b'W' => [0x11, 0x11, 0x11, 0x15, 0x15, 0x15, 0x0a],
        b'X' => [0x11, 0x11, 0x0a, 0x04, 0x0a, 0x11, 0x11],
        b'Y' => [0x11, 0x11, 0x0a, 0x04, 0x04, 0x04, 0x04],
        b'Z' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x10, 0x1f],
        b'0' => [0x0e, 0x11, 0x13, 0x15, 0x19, 0x11, 0x0e],
        b'1' => [0x04, 0x0c, 0x04, 0x04, 0x04, 0x04, 0x0e],
        b'2' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x08, 0x1f],
        b'3' => [0x1e, 0x01, 0x01, 0x0e, 0x01, 0x01, 0x1e],
        b'4' => [0x02, 0x06, 0x0a, 0x12, 0x1f, 0x02, 0x02],
        b'5' => [0x1f, 0x10, 0x10, 0x1e, 0x01, 0x01, 0x1e],
        b'6' => [0x0e, 0x10, 0x10, 0x1e, 0x11, 0x11, 0x0e],
        b'7' => [0x1f, 0x01, 0x02, 0x04, 0x08, 0x08, 0x08],
        b'8' => [0x0e, 0x11, 0x11, 0x0e, 0x11, 0x11, 0x0e],
        b'9' => [0x0e, 0x11, 0x11, 0x0f, 0x01, 0x01, 0x0e],
        b'>' => [0x10, 0x08, 0x04, 0x02, 0x04, 0x08, 0x10],
        b'<' => [0x01, 0x02, 0x04, 0x08, 0x04, 0x02, 0x01],
        b':' => [0x00, 0x04, 0x04, 0x00, 0x04, 0x04, 0x00],
        b'-' => [0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00],
        b'=' => [0x00, 0x00, 0x1f, 0x00, 0x1f, 0x00, 0x00],
        b',' => [0x00, 0x00, 0x00, 0x00, 0x04, 0x04, 0x08],
        b'.' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x0c],
        b'/' => [0x01, 0x02, 0x02, 0x04, 0x08, 0x08, 0x10],
        b'_' => [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f],
        b'!' => [0x04, 0x04, 0x04, 0x04, 0x04, 0x00, 0x04],
        b'?' => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
        _ => [0x0e, 0x11, 0x01, 0x02, 0x04, 0x00, 0x04],
    }
}
