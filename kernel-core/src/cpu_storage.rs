//! CPU bootstrap/tail arithmetic shared by production per-CPU consumers.
//!
//! Inline storage may cover a pre-heap bootstrap interval, but it is staging,
//! not a logical CPU ceiling. The tail is sized from the complete admitted CPU
//! count before hot-path publication.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CpuTailLayout {
    bootstrap: usize,
    admitted: usize,
}

impl CpuTailLayout {
    pub const fn new(bootstrap: usize, admitted: usize) -> Self {
        Self {
            bootstrap,
            admitted,
        }
    }

    pub const fn admitted(self) -> usize {
        self.admitted
    }

    pub const fn bootstrap_len(self) -> usize {
        if self.admitted < self.bootstrap {
            self.admitted
        } else {
            self.bootstrap
        }
    }

    pub const fn tail_len(self) -> usize {
        self.admitted.saturating_sub(self.bootstrap)
    }

    /// Return 0 for an inline slot or the heap-tail offset for a later CPU.
    pub const fn tail_index(self, cpu: usize) -> Option<usize> {
        if cpu >= self.admitted {
            return None;
        }
        if cpu < self.bootstrap {
            Some(0)
        } else {
            Some(cpu - self.bootstrap)
        }
    }

    /// True only when `cpu` belongs to the heap tail.
    pub const fn is_tail(self, cpu: usize) -> bool {
        cpu >= self.bootstrap && cpu < self.admitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_is_staging_not_the_logical_limit() {
        for admitted in [1, 32, 128, 129, 256, 1024] {
            let layout = CpuTailLayout::new(128, admitted);
            assert_eq!(layout.admitted(), admitted);
            assert_eq!(layout.bootstrap_len(), admitted.min(128));
            assert_eq!(layout.tail_len(), admitted.saturating_sub(128));
            assert_eq!(layout.tail_index(0), Some(0));
            assert_eq!(
                layout.tail_index(admitted - 1),
                Some((admitted - 1).saturating_sub(128))
            );
            assert_eq!(layout.tail_index(admitted), None);
            for cpu in 0..admitted {
                assert_eq!(layout.is_tail(cpu), cpu >= 128);
            }
        }
    }

    #[test]
    fn smaller_admission_never_aliases_an_inline_slot() {
        let layout = CpuTailLayout::new(128, 8);
        assert_eq!(layout.bootstrap_len(), 8);
        assert_eq!(layout.tail_len(), 0);
        assert_eq!(layout.tail_index(7), Some(0));
        assert_eq!(layout.tail_index(8), None);
        assert!(!layout.is_tail(7));
    }
}
