//! Bounded Vulkan WSI and normalized input compatibility state.
//!
//! 职责：维护有界窗口、surface、swapchain 图像轮转与输入事件队列。边界：
//! 不创建真实 X11/Wayland/DRM surface，不假设窗口服务器已经可用。
//! Responsibility: bounded WSI lifecycle and input transport without false display claims.

use alloc::vec::Vec;

pub const MAX_SWAPCHAIN_IMAGES: usize = 4;
pub const INPUT_QUEUE_CAPACITY: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowId(u64);

impl WindowId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceId(u64);

impl SurfaceId {
    pub const fn new(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowGeometry {
    pub width: u32,
    pub height: u32,
    pub scale_milli: u32,
}

impl WindowGeometry {
    pub fn validate(self) -> Result<Self, WsiError> {
        if self.width == 0
            || self.height == 0
            || self.width > 16_384
            || self.height > 16_384
            || self.scale_milli == 0
        {
            return Err(WsiError::InvalidGeometry);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    B8g8r8a8Srgb,
    R8g8b8a8Srgb,
    B8g8r8a8Unorm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PresentMode {
    Fifo,
    Mailbox,
    Immediate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurfaceCaps {
    pub formats: Vec<PixelFormat>,
    pub present_modes: Vec<PresentMode>,
    pub min_images: u8,
    pub max_images: u8,
}

impl SurfaceCaps {
    pub fn validate(&self) -> Result<Self, WsiError> {
        if self.formats.is_empty()
            || self.present_modes.is_empty()
            || self.min_images == 0
            || self.max_images < self.min_images
            || usize::from(self.max_images) > MAX_SWAPCHAIN_IMAGES
        {
            return Err(WsiError::InvalidSurfaceCaps);
        }
        Ok(self.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputValue {
    Key {
        keycode: u32,
        pressed: bool,
        repeat: bool,
    },
    PointerMove {
        x_milli: i32,
        y_milli: i32,
    },
    PointerButton {
        button: u32,
        pressed: bool,
    },
    Scroll {
        horizontal_milli: i32,
        vertical_milli: i32,
    },
    Focus(bool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputEvent {
    pub window: WindowId,
    pub serial: u64,
    pub value: InputValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WsiError {
    InvalidIdentity,
    InvalidGeometry,
    InvalidSurfaceCaps,
    Capacity,
    NotFound,
    StaleGeneration,
    SurfaceNotReady,
    ImageBusy,
    ImageNotAcquired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Window {
    id: WindowId,
    geometry: WindowGeometry,
    generation: u32,
    surface: Option<SurfaceId>,
}

impl Window {
    const fn empty() -> Self {
        Self {
            id: WindowId(0),
            geometry: WindowGeometry {
                width: 0,
                height: 0,
                scale_milli: 0,
            },
            generation: 0,
            surface: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Surface {
    id: SurfaceId,
    window: WindowId,
    generation: u32,
    geometry: WindowGeometry,
    caps: SurfaceCaps,
    acquired: [bool; MAX_SWAPCHAIN_IMAGES],
    next_image: u8,
    active: bool,
}

impl Surface {
    const fn empty() -> Self {
        Self {
            id: SurfaceId(0),
            window: WindowId(0),
            generation: 0,
            geometry: WindowGeometry {
                width: 0,
                height: 0,
                scale_milli: 0,
            },
            caps: SurfaceCaps {
                formats: Vec::new(),
                present_modes: Vec::new(),
                min_images: 0,
                max_images: 0,
            },
            acquired: [false; MAX_SWAPCHAIN_IMAGES],
            next_image: 0,
            active: false,
        }
    }
}

/// Bounded WSI compatibility state.
///
/// 有界 WSI 兼容状态；surface 和 input 都由窗口世代约束。
pub struct Wsi<const W: usize, const S: usize> {
    windows: [Window; W],
    surfaces: [Surface; S],
    input: [Option<InputEvent>; INPUT_QUEUE_CAPACITY],
    input_head: usize,
    input_len: usize,
    next_serial: u64,
    next_window_generation: u32,
    next_surface_generation: u32,
}

impl<const W: usize, const S: usize> Wsi<W, S> {
    pub const fn new() -> Self {
        assert!(W > 0 && S > 0, "WSI capacities must be non-zero");
        Self {
            windows: [Window::empty(); W],
            surfaces: [const { Surface::empty() }; S],
            input: [None; INPUT_QUEUE_CAPACITY],
            input_head: 0,
            input_len: 0,
            next_serial: 1,
            next_window_generation: 1,
            next_surface_generation: 1,
        }
    }

    pub fn register_window(
        &mut self,
        id: WindowId,
        geometry: WindowGeometry,
    ) -> Result<u32, WsiError> {
        let geometry = geometry.validate()?;
        if self.window(id).is_some() {
            return Err(WsiError::InvalidIdentity);
        }
        let slot = self
            .windows
            .iter_mut()
            .find(|window| window.generation == 0)
            .ok_or(WsiError::Capacity)?;
        let generation = self.next_window_generation;
        self.next_window_generation = generation.checked_add(1).ok_or(WsiError::Capacity)?;
        *slot = Window {
            id,
            geometry,
            generation,
            surface: None,
        };
        Ok(generation)
    }

    pub fn destroy_window(&mut self, id: WindowId) -> Result<usize, WsiError> {
        let slot = self.window_slot(id)?;
        for surface in &mut self.surfaces {
            if surface.active && surface.window == id {
                *surface = Surface::empty();
            }
        }
        self.windows[slot] = Window::empty();
        let mut removed = 0;
        while removed < self.input_len {
            let index = (self.input_head + removed) % INPUT_QUEUE_CAPACITY;
            if self.input[index].is_some_and(|event| event.window == id) {
                self.input[index] = None;
            } else {
                removed += 1;
                continue;
            }
            if removed + 1 < self.input_len {
                let last = (self.input_head + self.input_len - 1) % INPUT_QUEUE_CAPACITY;
                self.input[index] = self.input[last];
                self.input[last] = None;
            }
            self.input_len -= 1;
        }
        Ok(1)
    }

    pub fn resize(
        &mut self,
        id: WindowId,
        generation: u32,
        geometry: WindowGeometry,
    ) -> Result<u32, WsiError> {
        let geometry = geometry.validate()?;
        let slot = self.window_slot(id)?;
        let window = &mut self.windows[slot];
        if window.generation != generation {
            return Err(WsiError::StaleGeneration);
        }
        let next = generation.checked_add(1).ok_or(WsiError::Capacity)?;
        window.geometry = geometry;
        window.generation = next;
        window.surface = None;
        for surface in &mut self.surfaces {
            if surface.active && surface.window == id {
                *surface = Surface::empty();
            }
        }
        Ok(next)
    }

    pub fn create_surface(
        &mut self,
        id: SurfaceId,
        window: WindowId,
        caps: SurfaceCaps,
    ) -> Result<u32, WsiError> {
        let caps = caps.validate()?;
        let window_slot = self.window_slot(window)?;
        if self.surface(id).is_some() {
            return Err(WsiError::InvalidIdentity);
        }
        let window_state = &self.windows[window_slot];
        if window_state.surface.is_some() {
            return Err(WsiError::ImageBusy);
        }
        let slot = self
            .surfaces
            .iter_mut()
            .find(|surface| !surface.active)
            .ok_or(WsiError::Capacity)?;
        let generation = self.next_surface_generation;
        self.next_surface_generation = generation.checked_add(1).ok_or(WsiError::Capacity)?;
        *slot = Surface {
            id,
            window,
            generation,
            geometry: self.windows[window_slot].geometry,
            caps,
            acquired: [false; MAX_SWAPCHAIN_IMAGES],
            next_image: 0,
            active: true,
        };
        self.windows[window_slot].surface = Some(id);
        Ok(generation)
    }

    pub fn destroy_surface(&mut self, id: SurfaceId, generation: u32) -> Result<(), WsiError> {
        let slot = self.surface_slot(id)?;
        let surface = &self.surfaces[slot];
        if !surface.active || surface.generation != generation {
            return Err(WsiError::StaleGeneration);
        }
        if surface.acquired.iter().any(|acquired| *acquired) {
            return Err(WsiError::ImageBusy);
        }
        let window = surface.window;
        self.surfaces[slot] = Surface::empty();
        if let Some(window) = self.window_slot(window).ok().map(|slot| &mut self.windows[slot]) {
            window.surface = None;
        }
        Ok(())
    }

    pub fn acquire_image(
        &mut self,
        id: SurfaceId,
        generation: u32,
    ) -> Result<u32, WsiError> {
        let slot = self.surface_slot(id)?;
        let surface = &mut self.surfaces[slot];
        if !surface.active || surface.generation != generation {
            return Err(WsiError::StaleGeneration);
        }
        let count = usize::from(surface.caps.max_images);
        for _ in 0..count {
            let image = usize::from(surface.next_image);
            surface.next_image = (surface.next_image + 1) % surface.caps.max_images;
            if !surface.acquired[image] {
                surface.acquired[image] = true;
                return Ok(image as u32);
            }
        }
        Err(WsiError::ImageBusy)
    }

    pub fn present_image(
        &mut self,
        id: SurfaceId,
        generation: u32,
        image: u32,
    ) -> Result<(), WsiError> {
        let slot = self.surface_slot(id)?;
        let surface = &mut self.surfaces[slot];
        if !surface.active || surface.generation != generation {
            return Err(WsiError::StaleGeneration);
        }
        let image = usize::try_from(image).map_err(|_| WsiError::ImageNotAcquired)?;
        if image >= usize::from(surface.caps.max_images) || !surface.acquired[image] {
            return Err(WsiError::ImageNotAcquired);
        }
        surface.acquired[image] = false;
        Ok(())
    }

    pub fn push_input(
        &mut self,
        window: WindowId,
        generation: u32,
        value: InputValue,
    ) -> Result<u64, WsiError> {
        let slot = self.window_slot(window)?;
        if self.windows[slot].generation != generation {
            return Err(WsiError::StaleGeneration);
        }
        if self.input_len == INPUT_QUEUE_CAPACITY {
            return Err(WsiError::Capacity);
        }
        let serial = self.next_serial;
        self.next_serial = serial.checked_add(1).ok_or(WsiError::Capacity)?;
        let index = (self.input_head + self.input_len) % INPUT_QUEUE_CAPACITY;
        self.input[index] = Some(InputEvent {
            window,
            serial,
            value,
        });
        self.input_len += 1;
        Ok(serial)
    }

    pub fn pop_input(&mut self) -> Option<InputEvent> {
        if self.input_len == 0 {
            return None;
        }
        let event = self.input[self.input_head].take();
        self.input_head = (self.input_head + 1) % INPUT_QUEUE_CAPACITY;
        self.input_len -= 1;
        event
    }

    pub const fn input_len(&self) -> usize {
        self.input_len
    }

    fn window_slot(&self, id: WindowId) -> Result<usize, WsiError> {
        self.windows
            .iter()
            .position(|window| window.generation != 0 && window.id == id)
            .ok_or(WsiError::NotFound)
    }

    fn window(&self, id: WindowId) -> Option<&Window> {
        self.windows
            .iter()
            .find(|window| window.generation != 0 && window.id == id)
    }

    fn surface_slot(&self, id: SurfaceId) -> Result<usize, WsiError> {
        self.surfaces
            .iter()
            .position(|surface| surface.active && surface.id == id)
            .ok_or(WsiError::NotFound)
    }

    fn surface(&self, id: SurfaceId) -> Option<&Surface> {
        self.surfaces
            .iter()
            .find(|surface| surface.active && surface.id == id)
    }
}

impl<const W: usize, const S: usize> Default for Wsi<W, S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn caps() -> SurfaceCaps {
        SurfaceCaps {
            formats: vec![PixelFormat::B8g8r8a8Srgb],
            present_modes: vec![PresentMode::Fifo, PresentMode::Mailbox],
            min_images: 2,
            max_images: 3,
        }
    }

    #[test]
    fn surface_image_rotation_present_and_resize_revoke() {
        let window = WindowId::new(1).unwrap();
        let surface = SurfaceId::new(2).unwrap();
        let mut wsi = Wsi::<2, 2>::new();
        assert_eq!(
            wsi.register_window(
                window,
                WindowGeometry {
                    width: 1280,
                    height: 720,
                    scale_milli: 1000,
                }
            ),
            Ok(1)
        );
        assert_eq!(wsi.create_surface(surface, window, caps()), Ok(1));
        assert_eq!(wsi.acquire_image(surface, 1), Ok(0));
        assert_eq!(wsi.acquire_image(surface, 1), Ok(1));
        assert_eq!(wsi.acquire_image(surface, 1), Ok(2));
        assert_eq!(wsi.acquire_image(surface, 1), Err(WsiError::ImageBusy));
        wsi.present_image(surface, 1, 1).unwrap();
        assert_eq!(wsi.acquire_image(surface, 1), Ok(1));
        assert_eq!(
            wsi.resize(
                window,
                1,
                WindowGeometry {
                    width: 1920,
                    height: 1080,
                    scale_milli: 1000,
                }
            ),
            Ok(2)
        );
        assert_eq!(
            wsi.acquire_image(surface, 1),
            Err(WsiError::NotFound),
            "resize revokes the old surface rather than reviving its image set"
        );
        assert_eq!(wsi.create_surface(surface, window, caps()), Ok(2));
        assert_eq!(
            wsi.acquire_image(surface, 1),
            Err(WsiError::StaleGeneration)
        );
        assert_eq!(wsi.acquire_image(surface, 2), Ok(0));
    }

    #[test]
    fn input_queue_is_bounded_and_window_destroy_removes_events() {
        let window = WindowId::new(1).unwrap();
        let mut wsi = Wsi::<1, 1>::new();
        wsi.register_window(
            window,
            WindowGeometry {
                width: 1,
                height: 1,
                scale_milli: 1000,
            },
        )
        .unwrap();
        for _ in 0..INPUT_QUEUE_CAPACITY {
            wsi.push_input(
                window,
                1,
                InputValue::PointerButton {
                    button: 1,
                    pressed: true,
                },
            )
            .unwrap();
        }
        assert_eq!(
            wsi.push_input(window, 1, InputValue::Focus(true)),
            Err(WsiError::Capacity)
        );
        wsi.destroy_window(window).unwrap();
        assert_eq!(wsi.input_len(), 0);
        assert_eq!(
            wsi.push_input(window, 1, InputValue::Focus(true)),
            Err(WsiError::NotFound)
        );
        assert_eq!(
            wsi.register_window(
                window,
                WindowGeometry {
                    width: 2,
                    height: 2,
                    scale_milli: 1000,
                }
            ),
            Ok(2)
        );
        assert_eq!(
            wsi.push_input(window, 1, InputValue::Focus(true)),
            Err(WsiError::StaleGeneration)
        );
    }

    #[test]
    fn invalid_surface_and_single_window_surface_are_rejected() {
        let window = WindowId::new(1).unwrap();
        let mut wsi = Wsi::<1, 2>::new();
        wsi.register_window(
            window,
            WindowGeometry {
                width: 1,
                height: 1,
                scale_milli: 1000,
            },
        )
        .unwrap();
        let invalid = SurfaceCaps {
            formats: vec![],
            present_modes: vec![PresentMode::Fifo],
            min_images: 2,
            max_images: 1,
        };
        assert_eq!(
            wsi.create_surface(SurfaceId::new(2).unwrap(), window, invalid),
            Err(WsiError::InvalidSurfaceCaps)
        );
        wsi.create_surface(SurfaceId::new(2).unwrap(), window, caps())
            .unwrap();
        assert_eq!(
            wsi.create_surface(SurfaceId::new(3).unwrap(), window, caps()),
            Err(WsiError::ImageBusy)
        );
    }
}
