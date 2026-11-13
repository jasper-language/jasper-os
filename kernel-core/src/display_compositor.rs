//! Bounded native framebuffer compositor core.
//!
//! The compositor owns only layer metadata and paints caller-provided surfaces
//! into a caller-provided framebuffer. It does not own application memory,
//! implement a window manager, route input or execute GPU commands.
//!
//! 有界原生 framebuffer compositor 核心。compositor 只拥有 layer 元数据，并把
//! 调用方提供的 surface 合成到调用方 framebuffer；不拥有应用内存、不实现窗口
//! 管理器、不路由输入，也不执行 GPU 命令。

use crate::display_input::{DisplayInputError, PixelLayout, SurfaceSpec};

pub const MAX_COMPOSITOR_LAYERS: usize = 16;

/// Stable layer identity. A destroyed slot never revives the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerKey {
    slot: u16,
    generation: u32,
}

impl LayerKey {
    pub const fn to_raw(self) -> u64 {
        ((self.generation as u64) << 16) | self.slot as u64
    }

    pub const fn from_raw(raw: u64) -> Option<Self> {
        if raw == 0 || raw >> 48 != 0 || (raw >> 16) as u32 == 0 {
            return None;
        }
        Some(Self {
            slot: raw as u16,
            generation: (raw >> 16) as u32,
        })
    }
}

/// One registered visible surface. Position may be partially or fully offscreen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSpec {
    pub surface: SurfaceSpec,
    pub x: i32,
    pub y: i32,
    pub z_order: u16,
    pub visible: bool,
}

/// Immutable layer metadata returned to display clients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayerSnapshot {
    pub key: LayerKey,
    pub layer: LayerSpec,
}

/// Borrowed pixels supplied only for one composition pass.
#[derive(Clone, Copy, Debug)]
pub struct LayerPixels<'a> {
    pub key: LayerKey,
    pub bytes: &'a [u8],
}

/// Composition result for diagnostics and tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompositionStats {
    pub layers: usize,
    pub pixels: u64,
}

/// Compositor lifecycle. Open is the only mutable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositorState {
    Open,
    Closed,
    Failed,
}

/// Stable compositor errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompositorError {
    Unsupported,
    InvalidSurface,
    InvalidLayer,
    DuplicateOrder,
    Capacity,
    IdExhausted,
    StaleKey,
    MissingSurface,
    DuplicateSurface,
    Closed,
    Failed,
}

impl CompositorError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "system.display.compositor.error.unsupported",
            Self::InvalidSurface => "system.display.compositor.error.surface",
            Self::InvalidLayer => "system.display.compositor.error.layer",
            Self::DuplicateOrder => "system.display.compositor.error.order",
            Self::Capacity => "system.display.compositor.error.capacity",
            Self::IdExhausted => "system.display.compositor.error.ids",
            Self::StaleKey => "system.display.compositor.error.stale",
            Self::MissingSurface => "system.display.compositor.error.missing",
            Self::DuplicateSurface => "system.display.compositor.error.duplicate",
            Self::Closed => "system.display.compositor.error.closed",
            Self::Failed => "system.display.compositor.error.failed",
        }
    }
}

/// Fixed-capacity surface/layer registry.
pub struct Compositor<const N: usize> {
    layers: [Option<LayerSnapshot>; N],
    generations: [u32; N],
    state: CompositorState,
}

impl<const N: usize> Compositor<N> {
    pub const fn new() -> Self {
        Self {
            layers: [None; N],
            generations: [0; N],
            state: CompositorState::Open,
        }
    }

    pub const fn state(&self) -> CompositorState {
        self.state
    }

    pub fn count(&self) -> usize {
        self.layers.iter().flatten().count()
    }

    pub fn create(&mut self, layer: LayerSpec) -> Result<LayerKey, CompositorError> {
        if N == 0 {
            return Err(CompositorError::Unsupported);
        }
        self.ensure_open()?;
        validate_layer(layer)?;
        if layer.visible && self.visible_order_exists(layer.z_order, None) {
            return Err(CompositorError::DuplicateOrder);
        }
        let slot = self
            .layers
            .iter()
            .position(Option::is_none)
            .ok_or(CompositorError::Capacity)?;
        if slot > u16::MAX as usize {
            return Err(CompositorError::Capacity);
        }
        let generation = self.generations[slot]
            .checked_add(1)
            .ok_or(CompositorError::IdExhausted)?;
        let key = LayerKey {
            slot: slot as u16,
            generation,
        };
        self.generations[slot] = generation;
        self.layers[slot] = Some(LayerSnapshot { key, layer });
        Ok(key)
    }

    pub fn snapshot(&self, key: LayerKey) -> Result<LayerSnapshot, CompositorError> {
        self.ensure_open()?;
        self.record(key)
    }

    pub fn set_visible(&mut self, key: LayerKey, visible: bool) -> Result<(), CompositorError> {
        self.ensure_open()?;
        let layer = self.record(key)?.layer;
        if visible && self.visible_order_exists(layer.z_order, Some(key)) {
            return Err(CompositorError::DuplicateOrder);
        }
        self.layer_mut(key)?.layer.visible = visible;
        Ok(())
    }

    pub fn set_position(&mut self, key: LayerKey, x: i32, y: i32) -> Result<(), CompositorError> {
        self.ensure_open()?;
        let layer = self.layer_mut(key)?;
        layer.layer.x = x;
        layer.layer.y = y;
        Ok(())
    }

    pub fn set_order(&mut self, key: LayerKey, z_order: u16) -> Result<(), CompositorError> {
        self.ensure_open()?;
        let visible = self.record(key)?.layer.visible;
        if visible && self.visible_order_exists(z_order, Some(key)) {
            return Err(CompositorError::DuplicateOrder);
        }
        self.layer_mut(key)?.layer.z_order = z_order;
        Ok(())
    }

    pub fn destroy(&mut self, key: LayerKey) -> Result<(), CompositorError> {
        self.ensure_open()?;
        let _ = self.record(key)?;
        self.layers[key.slot as usize] = None;
        Ok(())
    }

    /// Copy visible layers in ascending z-order, clipping each to the frame.
    pub fn compose(
        &self,
        frame: SurfaceSpec,
        frame_bytes: &mut [u8],
        pixels: &[LayerPixels<'_>],
    ) -> Result<CompositionStats, CompositorError> {
        self.ensure_open()?;
        let frame_len = validate_surface(frame)?;
        if frame_bytes.len() as u64 != frame_len {
            return Err(CompositorError::InvalidSurface);
        }
        let mut ordered = [usize::MAX; N];
        let mut ordered_len = 0usize;
        for (slot, layer) in self.layers.iter().enumerate() {
            let Some(layer) = layer else {
                continue;
            };
            if !layer.layer.visible {
                continue;
            }
            if ordered_len == N {
                return Err(CompositorError::Capacity);
            }
            let mut at = ordered_len;
            while at != 0
                && self.layers[ordered[at - 1]]
                    .is_some_and(|previous| previous.layer.z_order > layer.layer.z_order)
            {
                ordered[at] = ordered[at - 1];
                at -= 1;
            }
            ordered[at] = slot;
            ordered_len += 1;
        }

        for (index, input) in pixels.iter().enumerate() {
            if pixels[..index]
                .iter()
                .any(|previous| previous.key == input.key)
            {
                return Err(CompositorError::DuplicateSurface);
            }
        }

        let mut written = 0u64;
        for slot in ordered[..ordered_len].iter().copied() {
            let layer = self.layers[slot].ok_or(CompositorError::StaleKey)?.layer;
            let input = pixels
                .iter()
                .find(|input| input.key == self.layers[slot].unwrap().key)
                .ok_or(CompositorError::MissingSurface)?;
            let source_len = validate_surface(layer.surface)?;
            if input.bytes.len() as u64 != source_len {
                return Err(CompositorError::InvalidSurface);
            }
            written = written.saturating_add(copy_layer(layer, input.bytes, frame, frame_bytes)?);
        }
        Ok(CompositionStats {
            layers: ordered_len,
            pixels: written,
        })
    }

    pub fn close(&mut self) -> Result<(), CompositorError> {
        match self.state {
            CompositorState::Open => {
                self.state = CompositorState::Closed;
                Ok(())
            }
            CompositorState::Closed => Ok(()),
            CompositorState::Failed => Err(CompositorError::Failed),
        }
    }

    pub fn fail(&mut self) -> Result<(), CompositorError> {
        match self.state {
            CompositorState::Open => {
                self.state = CompositorState::Failed;
                Ok(())
            }
            CompositorState::Failed => Ok(()),
            CompositorState::Closed => Err(CompositorError::Closed),
        }
    }

    fn ensure_open(&self) -> Result<(), CompositorError> {
        match self.state {
            CompositorState::Open => Ok(()),
            CompositorState::Closed => Err(CompositorError::Closed),
            CompositorState::Failed => Err(CompositorError::Failed),
        }
    }

    fn record(&self, key: LayerKey) -> Result<LayerSnapshot, CompositorError> {
        self.layers
            .get(key.slot as usize)
            .and_then(|layer| *layer)
            .filter(|layer| layer.key == key)
            .ok_or(CompositorError::StaleKey)
    }

    fn layer_mut(&mut self, key: LayerKey) -> Result<&mut LayerSnapshot, CompositorError> {
        self.layers
            .get_mut(key.slot as usize)
            .and_then(Option::as_mut)
            .filter(|layer| layer.key == key)
            .ok_or(CompositorError::StaleKey)
    }

    fn visible_order_exists(&self, z_order: u16, except: Option<LayerKey>) -> bool {
        self.layers.iter().flatten().any(|layer| {
            layer.layer.visible && layer.layer.z_order == z_order && Some(layer.key) != except
        })
    }
}

impl<const N: usize> Default for Compositor<N> {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_layer(layer: LayerSpec) -> Result<(), CompositorError> {
    let _ = validate_surface(layer.surface)?;
    if layer.surface.width == 0 || layer.surface.height == 0 {
        return Err(CompositorError::InvalidLayer);
    }
    Ok(())
}

fn validate_surface(surface: SurfaceSpec) -> Result<u64, CompositorError> {
    let bytes = surface.validate().map_err(|error| match error {
        DisplayInputError::Unsupported => CompositorError::Unsupported,
        _ => CompositorError::InvalidSurface,
    })?;
    if matches!(surface.layout, PixelLayout::Rgb | PixelLayout::Bgr) && surface.bytes_per_pixel < 3
    {
        return Err(CompositorError::InvalidSurface);
    }
    Ok(bytes)
}

fn copy_layer(
    layer: LayerSpec,
    source: &[u8],
    frame: SurfaceSpec,
    frame_bytes: &mut [u8],
) -> Result<u64, CompositorError> {
    let frame_width = i64::from(frame.width);
    let frame_height = i64::from(frame.height);
    let source_width = i64::from(layer.surface.width);
    let source_height = i64::from(layer.surface.height);
    let left = i64::from(layer.x).max(0);
    let top = i64::from(layer.y).max(0);
    let right = i64::from(layer.x)
        .checked_add(source_width)
        .ok_or(CompositorError::InvalidLayer)?
        .min(frame_width);
    let bottom = i64::from(layer.y)
        .checked_add(source_height)
        .ok_or(CompositorError::InvalidLayer)?
        .min(frame_height);
    if left >= right || top >= bottom {
        return Ok(0);
    }
    let mut written = 0u64;
    for destination_y in top..bottom {
        for destination_x in left..right {
            let source_x = destination_x - i64::from(layer.x);
            let source_y = destination_y - i64::from(layer.y);
            let (red, green, blue) = read_pixel(layer.surface, source, source_x, source_y)?;
            write_pixel(
                frame,
                frame_bytes,
                destination_x,
                destination_y,
                red,
                green,
                blue,
            )?;
            written += 1;
        }
    }
    Ok(written)
}

fn read_pixel(
    surface: SurfaceSpec,
    bytes: &[u8],
    x: i64,
    y: i64,
) -> Result<(u8, u8, u8), CompositorError> {
    let bpp = usize::from(surface.bytes_per_pixel);
    let offset = usize::try_from(
        y.checked_mul(i64::from(surface.stride))
            .and_then(|row| row.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(i64::from(surface.bytes_per_pixel)))
            .ok_or(CompositorError::InvalidSurface)?,
    )
    .map_err(|_| CompositorError::InvalidSurface)?;
    let pixel = bytes
        .get(offset..offset + bpp)
        .ok_or(CompositorError::InvalidSurface)?;
    Ok(match surface.layout {
        PixelLayout::Gray => (pixel[0], pixel[0], pixel[0]),
        PixelLayout::Rgb => (pixel[0], pixel[1], pixel[2]),
        PixelLayout::Bgr => (pixel[2], pixel[1], pixel[0]),
    })
}

fn write_pixel(
    surface: SurfaceSpec,
    bytes: &mut [u8],
    x: i64,
    y: i64,
    red: u8,
    green: u8,
    blue: u8,
) -> Result<(), CompositorError> {
    let bpp = usize::from(surface.bytes_per_pixel);
    let offset = usize::try_from(
        y.checked_mul(i64::from(surface.stride))
            .and_then(|row| row.checked_add(x))
            .and_then(|pixel| pixel.checked_mul(i64::from(surface.bytes_per_pixel)))
            .ok_or(CompositorError::InvalidSurface)?,
    )
    .map_err(|_| CompositorError::InvalidSurface)?;
    let pixel = bytes
        .get_mut(offset..offset + bpp)
        .ok_or(CompositorError::InvalidSurface)?;
    match surface.layout {
        PixelLayout::Gray => {
            pixel[0] = ((u16::from(red) + u16::from(green) + u16::from(blue)) / 3) as u8
        }
        PixelLayout::Rgb => {
            pixel[0] = red;
            pixel[1] = green;
            pixel[2] = blue;
        }
        PixelLayout::Bgr => {
            pixel[0] = blue;
            pixel[1] = green;
            pixel[2] = red;
        }
    }
    if bpp == 4 {
        pixel[3] = 0xff;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FRAME: SurfaceSpec = SurfaceSpec {
        width: 8,
        height: 4,
        stride: 8,
        bytes_per_pixel: 4,
        layout: PixelLayout::Bgr,
    };

    const RED_RGB: SurfaceSpec = SurfaceSpec {
        width: 2,
        height: 2,
        stride: 2,
        bytes_per_pixel: 3,
        layout: PixelLayout::Rgb,
    };

    fn layer(z_order: u16) -> LayerSpec {
        LayerSpec {
            surface: RED_RGB,
            x: 1,
            y: 1,
            z_order,
            visible: true,
        }
    }

    fn pixel(frame: &[u8], x: usize, y: usize) -> [u8; 4] {
        let at = (y * FRAME.stride as usize + x) * 4;
        frame[at..at + 4].try_into().unwrap()
    }

    #[test]
    fn registry_enforces_capacity_order_and_generations() {
        let mut compositor = Compositor::<1>::new();
        let key = compositor.create(layer(1)).unwrap();
        assert_eq!(compositor.create(layer(2)), Err(CompositorError::Capacity));
        compositor.destroy(key).unwrap();
        let replacement = compositor.create(layer(1)).unwrap();
        assert_ne!(key, replacement);
        assert_eq!(compositor.snapshot(key), Err(CompositorError::StaleKey));

        let mut ordered = Compositor::<2>::new();
        ordered.create(layer(1)).unwrap();
        assert_eq!(
            ordered.create(layer(1)),
            Err(CompositorError::DuplicateOrder)
        );
    }

    #[test]
    fn composition_orders_converts_and_clips_pixels() {
        let mut compositor = Compositor::<2>::new();
        let lower = compositor.create(layer(1)).unwrap();
        let upper = compositor
            .create(LayerSpec {
                surface: SurfaceSpec {
                    width: 2,
                    height: 1,
                    stride: 2,
                    bytes_per_pixel: 3,
                    layout: PixelLayout::Rgb,
                },
                x: 2,
                y: 1,
                z_order: 2,
                visible: true,
            })
            .unwrap();
        let blue = [0, 0, 255, 0, 0, 255];
        let red = [255, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0];
        let mut frame = [0u8; 8 * 4 * 4];
        let stats = compositor
            .compose(
                FRAME,
                &mut frame,
                &[
                    LayerPixels {
                        key: upper,
                        bytes: &blue,
                    },
                    LayerPixels {
                        key: lower,
                        bytes: &red,
                    },
                ],
            )
            .unwrap();
        assert_eq!(
            stats,
            CompositionStats {
                layers: 2,
                pixels: 6,
            }
        );
        assert_eq!(pixel(&frame, 2, 1), [255, 0, 0, 0xff]);
        compositor.set_order(upper, 0).unwrap();
        compositor
            .compose(
                FRAME,
                &mut frame,
                &[LayerPixels {
                    key: lower,
                    bytes: &red,
                }],
            )
            .unwrap_err();
    }

    #[test]
    fn packed_rgb_formats_require_a_complete_pixel() {
        let mut compositor = Compositor::<1>::new();
        assert_eq!(
            compositor.create(LayerSpec {
                surface: SurfaceSpec {
                    bytes_per_pixel: 1,
                    ..RED_RGB
                },
                x: 0,
                y: 0,
                z_order: 1,
                visible: true,
            }),
            Err(CompositorError::InvalidSurface)
        );
    }

    #[test]
    fn hidden_layers_need_no_pixels_and_negative_positions_clip() {
        let mut compositor = Compositor::<1>::new();
        let key = compositor
            .create(LayerSpec {
                x: -1,
                y: -1,
                visible: false,
                ..layer(1)
            })
            .unwrap();
        let mut frame = [0u8; 8 * 4 * 4];
        assert_eq!(
            compositor.compose(FRAME, &mut frame, &[]),
            Ok(CompositionStats {
                layers: 0,
                pixels: 0
            })
        );
        compositor.set_visible(key, true).unwrap();
        assert_eq!(
            compositor.compose(FRAME, &mut frame, &[]).unwrap_err(),
            CompositorError::MissingSurface
        );
        let red = [255u8, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0];
        assert_eq!(
            compositor
                .compose(FRAME, &mut frame, &[LayerPixels { key, bytes: &red }],)
                .unwrap()
                .pixels,
            1
        );
    }

    #[test]
    fn lifecycle_is_unique_and_closed_operations_fail() {
        let mut compositor = Compositor::<1>::new();
        let key = compositor.create(layer(1)).unwrap();
        compositor.close().unwrap();
        compositor.close().unwrap();
        assert_eq!(compositor.state(), CompositorState::Closed);
        assert_eq!(compositor.fail(), Err(CompositorError::Closed));
        assert_eq!(compositor.snapshot(key), Err(CompositorError::Closed));

        let mut failed = Compositor::<1>::new();
        failed.fail().unwrap();
        failed.fail().unwrap();
        assert_eq!(failed.state(), CompositorState::Failed);
        assert_eq!(failed.close(), Err(CompositorError::Failed));
    }

    #[test]
    fn layer_updates_change_the_next_composition_without_new_keys() {
        let mut compositor = Compositor::<2>::new();
        let lower = compositor.create(layer(1)).unwrap();
        let upper = compositor
            .create(LayerSpec {
                surface: RED_RGB,
                x: 2,
                y: 1,
                z_order: 2,
                visible: true,
            })
            .unwrap();
        let red = [255u8, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0];
        let blue = [0u8, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0, 255];
        let mut frame = [0u8; 8 * 4 * 4];
        compositor
            .compose(
                FRAME,
                &mut frame,
                &[
                    LayerPixels {
                        key: lower,
                        bytes: &red,
                    },
                    LayerPixels {
                        key: upper,
                        bytes: &blue,
                    },
                ],
            )
            .unwrap();
        assert_eq!(pixel(&frame, 2, 1), [255, 0, 0, 0xff]);

        compositor.set_order(upper, 0).unwrap();
        frame.fill(0);
        let stats = compositor
            .compose(
                FRAME,
                &mut frame,
                &[
                    LayerPixels {
                        key: lower,
                        bytes: &red,
                    },
                    LayerPixels {
                        key: upper,
                        bytes: &blue,
                    },
                ],
            )
            .unwrap();
        assert_eq!(stats.layers, 2);
        assert_eq!(pixel(&frame, 2, 1), [0, 0, 255, 0xff]);

        compositor.set_position(upper, 3, 1).unwrap();
        frame.fill(0);
        compositor
            .compose(
                FRAME,
                &mut frame,
                &[
                    LayerPixels {
                        key: lower,
                        bytes: &red,
                    },
                    LayerPixels {
                        key: upper,
                        bytes: &blue,
                    },
                ],
            )
            .unwrap();
        assert_eq!(pixel(&frame, 3, 1), [255, 0, 0, 0xff]);

        compositor.set_visible(upper, false).unwrap();
        assert!(compositor
            .compose(
                FRAME,
                &mut frame,
                &[LayerPixels {
                    key: lower,
                    bytes: &red,
                }],
            )
            .is_ok());
    }
}
