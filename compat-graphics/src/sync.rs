//! GPU fence and semaphore state with generation-checked lifetimes.
//!
//! 职责：表示 Vulkan 兼容层需要的有界 fence、binary semaphore 与 timeline
//! semaphore 状态。边界：不负责调度阻塞，不伪造设备完成；完成必须来自 GPU
//! queue 的真实 completion 路径。
//! Responsibility: bounded, generation-checked graphics synchronization state.

use core::cmp::Ordering;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncError {
    InvalidIdentity,
    InvalidState,
    StaleGeneration,
    NotReady,
    NonMonotonic,
    Overflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FenceStatus {
    Unsignaled,
    Signaled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fence {
    id: u64,
    generation: u32,
    signaled: bool,
}

impl Fence {
    pub fn new(id: u64, generation: u32, initially_signaled: bool) -> Result<Self, SyncError> {
        if id == 0 || generation == 0 {
            return Err(SyncError::InvalidIdentity);
        }
        Ok(Self {
            id,
            generation,
            signaled: initially_signaled,
        })
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn status(self) -> FenceStatus {
        if self.signaled {
            FenceStatus::Signaled
        } else {
            FenceStatus::Unsignaled
        }
    }

    pub fn reset(&mut self, generation: u32) -> Result<(), SyncError> {
        self.check(generation)?;
        self.signaled = false;
        Ok(())
    }

    pub fn signal(&mut self, generation: u32) -> Result<(), SyncError> {
        self.check(generation)?;
        if self.signaled {
            return Err(SyncError::InvalidState);
        }
        self.signaled = true;
        Ok(())
    }

    fn check(self, generation: u32) -> Result<(), SyncError> {
        if generation == self.generation {
            Ok(())
        } else {
            Err(SyncError::StaleGeneration)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Semaphore {
    id: u64,
    generation: u32,
    signaled: bool,
}

impl Semaphore {
    pub fn new(id: u64, generation: u32) -> Result<Self, SyncError> {
        if id == 0 || generation == 0 {
            return Err(SyncError::InvalidIdentity);
        }
        Ok(Self {
            id,
            generation,
            signaled: false,
        })
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn is_signaled(self) -> bool {
        self.signaled
    }

    /// Signals a binary semaphore exactly once without a wait in between.
    ///
    /// 无中间等待时二进制 semaphore 只能发布一次；重复 signal 失败关闭。
    pub fn signal(&mut self, generation: u32) -> Result<(), SyncError> {
        self.check(generation)?;
        if self.signaled {
            return Err(SyncError::InvalidState);
        }
        self.signaled = true;
        Ok(())
    }

    /// Consumes a signaled binary semaphore.
    ///
    /// 消费一次已触发的二进制 semaphore，未触发时拒绝。
    pub fn wait(&mut self, generation: u32) -> Result<SemaphoreWait, SyncError> {
        self.check(generation)?;
        if !self.signaled {
            return Err(SyncError::NotReady);
        }
        self.signaled = false;
        Ok(SemaphoreWait {
            semaphore: self.id,
            generation,
        })
    }

    fn check(self, generation: u32) -> Result<(), SyncError> {
        if generation == self.generation {
            Ok(())
        } else {
            Err(SyncError::StaleGeneration)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemaphoreWait {
    pub semaphore: u64,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimelineStatus {
    Ready,
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TimelineSemaphore {
    id: u64,
    generation: u32,
    value: u64,
}

impl TimelineSemaphore {
    pub fn new(id: u64, generation: u32, initial_value: u64) -> Result<Self, SyncError> {
        if id == 0 || generation == 0 {
            return Err(SyncError::InvalidIdentity);
        }
        Ok(Self {
            id,
            generation,
            value: initial_value,
        })
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    pub const fn value(self) -> u64 {
        self.value
    }

    pub fn signal(&mut self, generation: u32, value: u64) -> Result<u64, SyncError> {
        self.check(generation)?;
        match value.cmp(&self.value) {
            Ordering::Less => return Err(SyncError::NonMonotonic),
            Ordering::Equal => return Ok(self.value),
            Ordering::Greater => {}
        }
        self.value = value;
        Ok(self.value)
    }

    /// Advances a timeline for an already ordered queue completion.
    ///
    /// 为已完成队列工作推进 timeline。提交阶段已经验证严格递增顺序；若更高值先完成，
    /// 较晚完成且已被覆盖的较低值保持幂等，不回退时间线。
    /// Completion is idempotent when a higher value has already been published.
    pub(crate) fn satisfy_completion(
        &mut self,
        generation: u32,
        value: u64,
    ) -> Result<u64, SyncError> {
        self.check(generation)?;
        if value > self.value {
            self.value = value;
        }
        Ok(self.value)
    }

    pub fn wait(&self, generation: u32, value: u64) -> Result<TimelineStatus, SyncError> {
        self.check(generation)?;
        Ok(if value <= self.value {
            TimelineStatus::Ready
        } else {
            TimelineStatus::Pending
        })
    }

    fn check(self, generation: u32) -> Result<(), SyncError> {
        if generation == self.generation {
            Ok(())
        } else {
            Err(SyncError::StaleGeneration)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fence_binary_and_timeline_sync_enforce_states_and_generations() {
        let mut fence = Fence::new(1, 7, false).unwrap();
        assert_eq!(fence.status(), FenceStatus::Unsignaled);
        assert_eq!(fence.signal(6), Err(SyncError::StaleGeneration));
        fence.signal(7).unwrap();
        assert_eq!(fence.status(), FenceStatus::Signaled);
        assert_eq!(fence.signal(7), Err(SyncError::InvalidState));
        fence.reset(7).unwrap();
        assert_eq!(fence.status(), FenceStatus::Unsignaled);

        let mut binary = Semaphore::new(2, 7).unwrap();
        assert_eq!(binary.wait(7), Err(SyncError::NotReady));
        binary.signal(7).unwrap();
        assert_eq!(
            binary.signal(7),
            Err(SyncError::InvalidState),
            "binary semaphore signal must not accumulate"
        );
        assert_eq!(binary.wait(7), Ok(SemaphoreWait { semaphore: 2, generation: 7 }));
        assert!(!binary.is_signaled());

        let mut timeline = TimelineSemaphore::new(3, 7, 4).unwrap();
        assert_eq!(timeline.wait(7, 4), Ok(TimelineStatus::Ready));
        assert_eq!(timeline.wait(7, 5), Ok(TimelineStatus::Pending));
        assert_eq!(timeline.signal(7, 3), Err(SyncError::NonMonotonic));
        assert_eq!(timeline.signal(7, 5), Ok(5));
        assert_eq!(timeline.wait(7, 5), Ok(TimelineStatus::Ready));
    }
}
