//! Heap-backed CPU membership bitmap with no preset processor-count ceiling.
//!
//! This is the scalable phase-2 representation used after the heap is ready.
//! The existing copyable bootstrap `CpuSet` remains only for pre-heap code
//! until every production consumer migrates.
//!
//! 堆后备、无预设 CPU 数量上限的成员位图。堆就绪后使用该阶段 2 表示；现有可复制
//! bootstrap `CpuSet` 仅暂留于堆前代码，生产消费者仍需逐项迁移。

use alloc::vec::Vec;

/// Failure to construct or grow a dynamic CPU bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuBitmapError {
    /// The requested CPU or capacity cannot be represented by this address space.
    InvalidCpu,
    /// Heap allocation failed; existing membership remains unchanged.
    Allocation,
}

impl CpuBitmapError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidCpu => "system.cpu.error.invalid_cpu",
            Self::Allocation => "system.cpu.error.bitmap_allocation",
        }
    }
}

/// Variable-length CPU membership set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CpuBitmap {
    words: Vec<u64>,
}

impl CpuBitmap {
    /// Create storage for at least `capacity` possible CPU indices.
    pub fn with_capacity(capacity: usize) -> Result<Self, CpuBitmapError> {
        let words = words_for(capacity)?;
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(words)
            .map_err(|_| CpuBitmapError::Allocation)?;
        storage.resize(words, 0);
        Ok(Self { words: storage })
    }

    /// Empty set with no allocated words.
    pub const fn empty() -> Self {
        Self { words: Vec::new() }
    }

    /// Convert the legacy fixed CPU set into scalable storage.
    ///
    /// This adapter is temporary for consumers whose inputs still arrive
    /// through the copyable bootstrap ABI.
    pub fn from_cpu_set(set: crate::smp::CpuSet) -> Result<Self, CpuBitmapError> {
        let mut bitmap = Self::empty();
        for cpu in set.iter() {
            bitmap.insert(cpu)?;
        }
        Ok(bitmap)
    }

    /// Create a set containing processors `0..count`.
    pub fn first(count: usize) -> Result<Self, CpuBitmapError> {
        let mut set = Self::with_capacity(count)?;
        let full_words = count / 64;
        for word in &mut set.words[..full_words] {
            *word = u64::MAX;
        }
        if count % 64 != 0 {
            set.words[full_words] = (1u64 << (count % 64)) - 1;
        }
        Ok(set)
    }

    /// Represented bits rounded up to whole 64-bit words.
    pub fn capacity_bits(&self) -> Result<usize, CpuBitmapError> {
        self.words
            .len()
            .checked_mul(64)
            .ok_or(CpuBitmapError::InvalidCpu)
    }

    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|word| *word == 0)
    }

    /// Remove every member while retaining allocated storage for hot paths.
    pub fn clear(&mut self) {
        self.words.clear();
    }

    pub fn len(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }

    pub fn contains(&self, cpu: usize) -> bool {
        let Some((index, mask)) = word_mask(cpu) else {
            return false;
        };
        self.words.get(index).is_some_and(|word| word & mask != 0)
    }

    /// Insert one CPU, growing the backing set when required.
    pub fn insert(&mut self, cpu: usize) -> Result<(), CpuBitmapError> {
        let (index, mask) = word_mask(cpu).ok_or(CpuBitmapError::InvalidCpu)?;
        let needed = index.checked_add(1).ok_or(CpuBitmapError::InvalidCpu)?;
        if needed > self.words.len() {
            self.words
                .try_reserve(needed - self.words.len())
                .map_err(|_| CpuBitmapError::Allocation)?;
            self.words.resize(needed, 0);
        }
        self.words[index] |= mask;
        Ok(())
    }

    /// Remove one CPU. Removing an out-of-range CPU is a no-op.
    pub fn remove(&mut self, cpu: usize) {
        let Some((index, mask)) = word_mask(cpu) else {
            return;
        };
        if let Some(word) = self.words.get_mut(index) {
            *word &= !mask;
        }
    }

    /// Number of members in ascending CPU-index order.
    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.words.iter().enumerate().flat_map(|(index, word)| {
            let mut bits = *word;
            core::iter::from_fn(move || {
                if bits == 0 {
                    return None;
                }
                let offset = bits.trailing_zeros() as usize;
                bits &= bits - 1;
                Some(index * 64 + offset)
            })
        })
    }

    /// Borrow the backing words for zero-allocation composite iterators.
    pub(crate) fn words(&self) -> &[u64] {
        &self.words
    }

    pub fn union(&self, other: &Self) -> Result<Self, CpuBitmapError> {
        let words = self.words.len().max(other.words.len());
        let mut result = Self::with_words(words)?;
        for (index, word) in result.words.iter_mut().enumerate() {
            *word = self.words.get(index).copied().unwrap_or(0)
                | other.words.get(index).copied().unwrap_or(0);
        }
        Ok(result)
    }

    pub fn intersect(&self, other: &Self) -> Result<Self, CpuBitmapError> {
        let words = self.words.len().min(other.words.len());
        let mut result = Self::with_words(words)?;
        for (index, word) in result.words.iter_mut().enumerate() {
            *word = self.words[index] & other.words[index];
        }
        Ok(result)
    }

    /// Remove every member present in `other`.
    pub fn remove_all(&mut self, other: &Self) {
        for (index, word) in self.words.iter_mut().enumerate() {
            if let Some(remove) = other.words.get(index) {
                *word &= !*remove;
            }
        }
    }

    /// Copy membership into this preallocated bitmap without growing it.
    ///
    /// Returns [`CpuBitmapError::Allocation`] when the destination lacks the
    /// words needed for the source. Callers use this on IRQ/timer hot paths
    /// after reserving storage outside the protected transaction.
    pub fn copy_from(&mut self, other: &Self) -> Result<(), CpuBitmapError> {
        if other.words.len() > self.words.len() {
            return Err(CpuBitmapError::Allocation);
        }
        let source_len = other.words.len();
        self.words[..source_len].copy_from_slice(&other.words);
        self.words[source_len..].fill(0);
        Ok(())
    }

    /// Replace membership from the legacy mask without growing this bitmap.
    pub fn copy_from_cpu_set(&mut self, other: crate::smp::CpuSet) -> Result<(), CpuBitmapError> {
        let required_bits = other.iter().max().map_or(0, |cpu| cpu.saturating_add(1));
        if required_bits > self.capacity_bits()? {
            return Err(CpuBitmapError::Allocation);
        }
        self.words.fill(0);
        for cpu in other.iter() {
            self.insert(cpu)?;
        }
        Ok(())
    }

    /// Borrow the set as the legacy mask when every member is representable.
    pub fn to_cpu_set(&self) -> Option<crate::smp::CpuSet> {
        let mut legacy = crate::smp::CpuSet::EMPTY;
        for cpu in self.iter() {
            if !legacy.insert(cpu) {
                return None;
            }
        }
        Some(legacy)
    }

    fn with_words(words: usize) -> Result<Self, CpuBitmapError> {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(words)
            .map_err(|_| CpuBitmapError::Allocation)?;
        storage.resize(words, 0);
        Ok(Self { words: storage })
    }
}

fn words_for(bits: usize) -> Result<usize, CpuBitmapError> {
    bits.checked_add(63)
        .map(|rounded| rounded / 64)
        .ok_or(CpuBitmapError::InvalidCpu)
}

fn word_mask(cpu: usize) -> Option<(usize, u64)> {
    let index = cpu / 64;
    let mask = 1u64.checked_shl((cpu % 64) as u32)?;
    Some((index, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_high_cpu_membership_grows_without_fixed_count_ceiling() {
        for cpu in [1usize, 32, 64, 128, 129, 256, 1024, 4096] {
            let mut set = CpuBitmap::empty();
            set.insert(cpu).unwrap();
            assert!(set.contains(cpu));
            assert_eq!(set.iter().collect::<Vec<_>>(), vec![cpu]);
        }
    }

    #[test]
    fn first_union_intersection_and_removal_are_exact() {
        let first = CpuBitmap::first(130).unwrap();
        assert_eq!(first.len(), 130);
        assert!(first.contains(129));
        assert!(!first.contains(130));

        let mut high = CpuBitmap::empty();
        high.insert(65).unwrap();
        high.insert(1024).unwrap();
        let union = first.union(&high).unwrap();
        assert_eq!(union.len(), 131);
        let intersection = first.intersect(&high).unwrap();
        assert_eq!(intersection.iter().collect::<Vec<_>>(), vec![65]);

        let mut removed = union;
        removed.remove_all(&high);
        assert_eq!(removed.len(), 129);
        assert!(removed.contains(64));
        assert!(!removed.contains(65));
        assert!(!removed.contains(1024));
    }

    #[test]
    fn empty_and_capacity_boundaries_are_explicit() {
        assert!(CpuBitmap::empty().is_empty());
        assert!(CpuBitmap::first(0).unwrap().is_empty());
        assert_eq!(
            CpuBitmap::first(1).unwrap().iter().collect::<Vec<_>>(),
            vec![0]
        );
        assert_eq!(CpuBitmap::first(64).unwrap().capacity_bits(), Ok(64));
        assert_eq!(CpuBitmap::first(65).unwrap().capacity_bits(), Ok(128));
    }

    #[test]
    fn clear_reuses_hot_path_storage() {
        let mut set = CpuBitmap::first(130).unwrap();
        set.clear();
        assert!(set.is_empty());
        set.insert(129).unwrap();
        assert!(set.contains(129));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn copy_from_requires_preallocated_destination() {
        let source = CpuBitmap::first(130).unwrap();
        let mut destination = CpuBitmap::with_capacity(130).unwrap();
        destination.copy_from(&source).unwrap();
        assert_eq!(destination, source);

        let mut too_small = CpuBitmap::first(64).unwrap();
        assert_eq!(
            too_small.copy_from(&source),
            Err(CpuBitmapError::Allocation)
        );
        assert_eq!(too_small, CpuBitmap::first(64).unwrap());
    }

    #[test]
    fn legacy_mask_copy_never_grows_destination() {
        let mut destination = CpuBitmap::with_capacity(130).unwrap();
        destination
            .copy_from_cpu_set(crate::smp::CpuSet::first(128))
            .unwrap();
        assert_eq!(destination.len(), 128);

        let mut too_small = CpuBitmap::first(64).unwrap();
        assert_eq!(
            too_small.copy_from_cpu_set(crate::smp::CpuSet::first(65)),
            Err(CpuBitmapError::Allocation)
        );
        assert_eq!(
            too_small,
            CpuBitmap::from_cpu_set(crate::smp::CpuSet::first(64)).unwrap()
        );
        assert_eq!(
            destination.to_cpu_set(),
            Some(crate::smp::CpuSet::first(128))
        );
    }
}
