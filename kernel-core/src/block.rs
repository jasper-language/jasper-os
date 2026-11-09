//! Block-I/O request contract for the native virtio-blk driver.

pub const SECTOR_BYTES: u64 = 512;
pub const IO_ALIGNMENT: u64 = 4096;
pub const SECTORS_PER_IO_UNIT: u64 = IO_ALIGNMENT / SECTOR_BYTES;
pub const HEADER_BYTES: usize = 16;
pub const DISCARD_RANGE_BYTES: usize = 16;
pub const STATUS_BYTES: usize = 1;
pub const MAX_DATA_PAGES: usize = 14;

pub const TYPE_IN: u32 = 0;
pub const TYPE_OUT: u32 = 1;
pub const TYPE_FLUSH: u32 = 4;
pub const TYPE_DISCARD: u32 = 11;

pub const STATUS_OK: u8 = 0;
pub const STATUS_IOERR: u8 = 1;
pub const STATUS_UNSUPPORTED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Features {
    pub flush: bool,
    pub discard: bool,
    pub block_size: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    Read,
    Write,
    Flush,
    Discard,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub kind: RequestKind,
    pub sector: u64,
    pub pages: u64,
    pub fua: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Alignment,
    Range,
    Unsupported,
    ChainTooLong,
}

impl Request {
    pub const fn read(sector: u64, pages: u64) -> Self {
        Self {
            kind: RequestKind::Read,
            sector,
            pages,
            fua: false,
        }
    }

    pub const fn write(sector: u64, pages: u64, fua: bool) -> Self {
        Self {
            kind: RequestKind::Write,
            sector,
            pages,
            fua,
        }
    }

    pub const fn flush() -> Self {
        Self {
            kind: RequestKind::Flush,
            sector: 0,
            pages: 0,
            fua: false,
        }
    }

    pub const fn discard(sector: u64, pages: u64) -> Self {
        Self {
            kind: RequestKind::Discard,
            sector,
            pages,
            fua: false,
        }
    }

    pub fn validate(self, features: Features, capacity_sectors: u64) -> Result<(), Error> {
        match self.kind {
            RequestKind::Read | RequestKind::Write => {
                if self.pages == 0 {
                    return Err(Error::Range);
                }
                if self.pages > MAX_DATA_PAGES as u64 {
                    return Err(Error::ChainTooLong);
                }
                if self.fua && !features.flush {
                    return Err(Error::Unsupported);
                }
            }
            RequestKind::Flush => {
                if self.sector != 0 || self.pages != 0 || self.fua {
                    return Err(Error::Range);
                }
                if !features.flush {
                    return Err(Error::Unsupported);
                }
            }
            RequestKind::Discard => {
                if self.pages == 0 {
                    return Err(Error::Range);
                }
                if !features.discard {
                    return Err(Error::Unsupported);
                }
            }
        }
        if self.sector % SECTORS_PER_IO_UNIT != 0 {
            return Err(Error::Alignment);
        }
        if self.pages == 0 {
            return Ok(());
        }
        let sectors = self
            .pages
            .checked_mul(SECTORS_PER_IO_UNIT)
            .ok_or(Error::Range)?;
        let end = self.sector.checked_add(sectors).ok_or(Error::Range)?;
        if end > capacity_sectors {
            return Err(Error::Range);
        }
        Ok(())
    }

    pub fn wire_type(self) -> u32 {
        let kind = match self.kind {
            RequestKind::Read => TYPE_IN,
            RequestKind::Write => TYPE_OUT,
            RequestKind::Flush => TYPE_FLUSH,
            RequestKind::Discard => TYPE_DISCARD,
        };
        // virtio-blk has no FUA request bit. The driver implements FUA as
        // successful write followed by a flush, so the wire type stays WRITE.
        kind
    }

    pub fn header(self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        out[0..4].copy_from_slice(&self.wire_type().to_le_bytes());
        out[8..16].copy_from_slice(&self.sector.to_le_bytes());
        out
    }

    pub fn discard_range(self) -> [u8; DISCARD_RANGE_BYTES] {
        let mut out = [0u8; DISCARD_RANGE_BYTES];
        if self.kind == RequestKind::Discard {
            out[0..8].copy_from_slice(&self.sector.to_le_bytes());
            let sectors = self.pages.saturating_mul(SECTORS_PER_IO_UNIT);
            out[8..16].copy_from_slice(&sectors.to_le_bytes());
        }
        out
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Terminal {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Submitted,
    Terminal(Terminal),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lifecycle {
    state: State,
    cancel_requested: bool,
}

impl Lifecycle {
    pub const fn new() -> Self {
        Self {
            state: State::Ready,
            cancel_requested: false,
        }
    }

    pub const fn state(self) -> State {
        self.state
    }

    pub const fn cancel_requested(self) -> bool {
        self.cancel_requested
    }

    pub fn submit(&mut self) -> Result<(), State> {
        if self.state != State::Ready {
            return Err(self.state);
        }
        self.state = State::Submitted;
        Ok(())
    }

    /// Record cancellation without releasing the device chain. A submitted I/O
    /// still has to reach its hardware terminal before DMA memory is released.
    pub fn cancel(&mut self) -> Result<(), State> {
        match self.state {
            State::Ready => {
                self.state = State::Terminal(Terminal::Cancelled);
                Ok(())
            }
            State::Submitted => {
                self.cancel_requested = true;
                Ok(())
            }
            State::Terminal(_) => Err(self.state),
        }
    }

    pub fn complete(&mut self, status: u8) -> Result<Terminal, State> {
        if self.state != State::Submitted {
            return Err(self.state);
        }
        let terminal = if self.cancel_requested {
            Terminal::Cancelled
        } else if status == STATUS_OK {
            Terminal::Completed
        } else {
            Terminal::Failed
        };
        self.state = State::Terminal(terminal);
        Ok(terminal)
    }
}

impl Default for Lifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEATURES: Features = Features {
        flush: true,
        discard: true,
        block_size: true,
    };

    #[test]
    fn admission_requires_4k_alignment_and_capacity() {
        assert_eq!(Request::read(8, 1).validate(FEATURES, 16), Ok(()));
        assert_eq!(
            Request::read(1, 1).validate(FEATURES, 16),
            Err(Error::Alignment)
        );
        assert_eq!(
            Request::read(16, 1).validate(FEATURES, 16),
            Err(Error::Range)
        );
        assert_eq!(
            Request::write(0, 0, false).validate(FEATURES, 16),
            Err(Error::Range)
        );
        assert_eq!(
            Request::write(0, MAX_DATA_PAGES as u64 + 1, false)
                .validate(FEATURES, u64::MAX),
            Err(Error::ChainTooLong)
        );
    }

    #[test]
    fn optional_operations_fail_closed() {
        let no_optional = Features {
            flush: false,
            discard: false,
            block_size: false,
        };
        assert_eq!(
            Request::flush().validate(no_optional, 16),
            Err(Error::Unsupported)
        );
        assert_eq!(
            Request::discard(0, 1).validate(no_optional, 16),
            Err(Error::Unsupported)
        );
        assert_eq!(
            Request::write(0, 1, true).validate(no_optional, 16),
            Err(Error::Unsupported)
        );
    }

    #[test]
    fn cancel_and_completion_publish_one_terminal() {
        let mut cancelled = Lifecycle::new();
        assert_eq!(cancelled.cancel(), Ok(()));
        assert_eq!(cancelled.state(), State::Terminal(Terminal::Cancelled));
        assert_eq!(cancelled.complete(STATUS_OK), Err(cancelled.state()));

        let mut submitted = Lifecycle::new();
        submitted.submit().unwrap();
        submitted.cancel().unwrap();
        assert!(submitted.cancel_requested());
        assert_eq!(submitted.complete(STATUS_OK), Ok(Terminal::Cancelled));
        assert_eq!(submitted.state(), State::Terminal(Terminal::Cancelled));
        assert_eq!(submitted.cancel(), Err(submitted.state()));
    }

    #[test]
    fn wire_header_and_request_flags_are_explicit() {
        let request = Request::write(24, 2, true);
        let header = request.header();
        assert_eq!(
            u32::from_le_bytes(header[0..4].try_into().unwrap()),
            TYPE_OUT
        );
        assert_eq!(u32::from_le_bytes(header[4..8].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(header[8..16].try_into().unwrap()), 24);
    }
}
