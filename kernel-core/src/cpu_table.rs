//! Bootstrap-inline plus heap-tail storage indexed by admitted logical CPU.

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTableError {
    Allocation,
}

pub struct CpuTable<T, const N: usize> {
    inline: [T; N],
    extra: Vec<T>,
}

impl<T, const N: usize> CpuTable<T, N> {
    pub const fn new(inline: [T; N]) -> Self {
        Self {
            inline,
            extra: Vec::new(),
        }
    }

    pub fn len(&self) -> usize {
        N + self.extra.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn get(&self, cpu: usize) -> Option<&T> {
        if cpu < N {
            self.inline.get(cpu)
        } else {
            self.extra.get(cpu - N)
        }
    }

    pub fn prepare_tail(
        &self,
        total: usize,
        mut fill: impl FnMut() -> T,
    ) -> Result<Vec<T>, CpuTableError> {
        if total <= self.len() {
            return Ok(Vec::new());
        }
        let needed = total - self.len();
        let mut tail = Vec::new();
        tail.try_reserve_exact(needed)
            .map_err(|_| CpuTableError::Allocation)?;
        for _ in 0..needed {
            tail.push(fill());
        }
        Ok(tail)
    }

    pub fn commit_tail(&mut self, tail: Vec<T>) {
        self.extra.extend(tail);
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut T> {
        self.inline.iter_mut().chain(self.extra.iter_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.inline.iter().chain(self.extra.iter())
    }

    pub fn fill(&mut self, value: T)
    where
        T: Clone,
    {
        for slot in self.iter_mut() {
            *slot = value.clone();
        }
    }
}

impl<T, const N: usize> core::ops::Index<usize> for CpuTable<T, N> {
    type Output = T;

    fn index(&self, cpu: usize) -> &Self::Output {
        self.get(cpu).expect("admitted CPU index")
    }
}

impl<T, const N: usize> core::ops::IndexMut<usize> for CpuTable<T, N> {
    fn index_mut(&mut self, cpu: usize) -> &mut Self::Output {
        if cpu < N {
            &mut self.inline[cpu]
        } else {
            &mut self.extra[cpu - N]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_from_bootstrap_to_sparse_129_and_256_cpu_rows() {
        let mut table = CpuTable::new([0u64; 128]);
        let first = table.prepare_tail(129, || 0).unwrap();
        assert_eq!(first.len(), 1);
        table.commit_tail(first);
        table[128] = 129;
        assert_eq!(table.len(), 129);
        assert_eq!(table.get(128), Some(&129));

        let second = table.prepare_tail(256, || 0).unwrap();
        assert_eq!(second.len(), 127);
        table.commit_tail(second);
        table[255] = 256;
        assert_eq!(table.len(), 256);
        assert_eq!(table.get(255), Some(&256));
        assert_eq!(table.get(256), None);
    }

    #[test]
    fn failed_tail_reservation_does_not_change_published_table() {
        let table = CpuTable::new([7u8; 128]);
        let result = table.prepare_tail(usize::MAX, || 7);
        assert!(result.is_err());
        assert_eq!(table.len(), 128);
        assert_eq!(table.get(127), Some(&7));
        assert_eq!(table.get(128), None);
    }
}
