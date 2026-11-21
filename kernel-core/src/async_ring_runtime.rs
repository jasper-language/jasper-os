//! Runtime-capacity async-ring state machine for the production kernel.
//!
//! The ABI-only `AsyncRing<C, N>` remains allocation-free for user-side checks
//! and Kani. The kernel uses this heap-backed state machine so completion,
//! control-block and history capacities come from the ring creation request
//! and admitted resource budget instead of a compiled shape.
//! 生产内核使用运行时容量的异步环状态机；ABI-only 的固定形状实现继续供
//! 无分配器用户侧检查和 Kani 使用。

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use crate::async_ring::{
    Cancelled, CancelError, Completion, Exec, ProgressError, RingStats, Submission, SubmitError,
    Terminal,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Queued,
    Running(Exec),
}

#[derive(Debug, Clone, Copy)]
struct Block {
    id: u64,
    sub: Submission,
    phase: Phase,
    decided: Option<Terminal>,
    quiesced: bool,
    published: bool,
    dropped: bool,
}

/// Allocation-backed async-ring state machine.
/// 堆后备、容量由创建请求决定的异步环状态机。
pub struct RuntimeAsyncRing {
    capacity: usize,
    blocks_capacity: usize,
    cq: VecDeque<Completion>,
    window: VecDeque<(u64, Terminal)>,
    blocks: Vec<Option<Block>>,
    reserved: usize,
    next_id: u64,
    id_limit: u64,
    closing: bool,
    reclaimed: VecDeque<u64>,
    stats: RingStats,
}

impl RuntimeAsyncRing {
    /// Allocate every runtime table before publishing the ring. Any allocation
    /// failure returns `None` without a partially initialized state machine.
    /// 发布环之前完成全部运行时表分配；任一失败都不留下部分初始化状态。
    pub fn new(capacity: usize, blocks_capacity: usize) -> Option<Self> {
        if capacity == 0 || blocks_capacity == 0 || capacity > blocks_capacity {
            return None;
        }

        let mut cq = VecDeque::new();
        cq.try_reserve_exact(capacity).ok()?;
        let mut window = VecDeque::new();
        window.try_reserve_exact(capacity).ok()?;
        let mut blocks = Vec::new();
        blocks.try_reserve_exact(blocks_capacity).ok()?;
        blocks.resize_with(blocks_capacity, || None);
        let mut reclaimed = VecDeque::new();
        reclaimed.try_reserve_exact(blocks_capacity).ok()?;

        Some(Self {
            capacity,
            blocks_capacity,
            cq,
            window,
            blocks,
            reserved: 0,
            next_id: 1,
            id_limit: u64::MAX,
            closing: false,
            reclaimed,
            stats: RingStats::default(),
        })
    }

    /// Lower the last assignable request ID; never raises it.
    pub fn limit_ids(&mut self, last_id: u64) {
        self.id_limit = self.id_limit.min(last_id);
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn blocks_capacity(&self) -> usize {
        self.blocks_capacity
    }

    pub fn credits(&self) -> usize {
        self.capacity - self.reserved - self.cq.len()
    }

    pub fn reserved(&self) -> usize {
        self.reserved
    }

    pub fn ready(&self) -> usize {
        self.cq.len()
    }

    pub fn in_flight(&self) -> usize {
        self.blocks.iter().filter(|block| block.is_some()).count()
    }

    pub fn decided_unpublished(&self) -> usize {
        self.blocks
            .iter()
            .flatten()
            .filter(|block| block.decided.is_some() && !block.published)
            .count()
    }

    pub fn is_closing(&self) -> bool {
        self.closing
    }

    pub fn is_drained(&self) -> bool {
        self.closing && self.in_flight() == 0
    }

    pub fn stats(&self) -> RingStats {
        self.stats
    }

    pub fn next_id(&self) -> u64 {
        self.next_id
    }

    fn slot_of(&self, id: u64) -> Option<usize> {
        self.blocks
            .iter()
            .position(|block| matches!(block, Some(block) if block.id == id))
    }

    pub fn submit(&mut self, sub: Submission) -> Result<u64, SubmitError> {
        let slot = match self.check_submit() {
            Ok(slot) => slot,
            Err(error) => {
                self.stats.rejected += 1;
                return Err(error);
            }
        };
        let id = self.next_id;
        self.next_id += 1;
        self.reserved += 1;
        self.blocks[slot] = Some(Block {
            id,
            sub,
            phase: Phase::Queued,
            decided: None,
            quiesced: true,
            published: false,
            dropped: false,
        });
        self.stats.accepted += 1;
        Ok(id)
    }

    fn check_submit(&self) -> Result<usize, SubmitError> {
        if self.closing {
            return Err(SubmitError::Closing);
        }
        if self.next_id > self.id_limit || self.next_id == u64::MAX {
            return Err(SubmitError::IdExhausted);
        }
        if self.credits() == 0 {
            return Err(SubmitError::CqFull);
        }
        self.blocks
            .iter()
            .position(Option::is_none)
            .ok_or(SubmitError::QuotaExceeded)
    }

    pub fn decision(&self, id: u64) -> Option<Option<Terminal>> {
        self.slot_of(id)
            .and_then(|slot| self.blocks[slot].as_ref())
            .map(|block| block.decided)
    }

    pub fn start(&mut self, id: u64, exec: Exec) -> Result<(), ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if block.phase != Phase::Queued || block.decided.is_some() {
            return Err(ProgressError::NoSuchRequest);
        }
        block.phase = Phase::Running(exec);
        block.quiesced = false;
        Ok(())
    }

    pub fn finish(&mut self, id: u64, value: i64) -> Result<Terminal, ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if !matches!(block.phase, Phase::Running(_)) || block.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        let terminal = *block.decided.get_or_insert(Terminal::Done(value));
        block.quiesced = true;
        self.advance(slot);
        Ok(terminal)
    }

    pub fn quiesce(&mut self, id: u64) -> Result<(), ProgressError> {
        let slot = self.slot_of(id).ok_or(ProgressError::NoSuchRequest)?;
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(ProgressError::NoSuchRequest)?;
        if block.decided.is_none() || block.quiesced {
            return Err(ProgressError::NoSuchRequest);
        }
        block.quiesced = true;
        self.advance(slot);
        Ok(())
    }

    pub fn cancel(&mut self, id: u64) -> Result<Cancelled, CancelError> {
        let Some(slot) = self.slot_of(id) else {
            return if self.window.iter().any(|(request_id, _)| *request_id == id) {
                Err(CancelError::AlreadyCompleted)
            } else {
                Err(CancelError::NotFound)
            };
        };
        let block = self.blocks[slot]
            .as_mut()
            .ok_or(CancelError::NotFound)?;
        if block.decided.is_some() {
            return Err(CancelError::AlreadyCompleted);
        }
        let cancelled = match block.phase {
            Phase::Queued => Cancelled::NotStarted,
            Phase::Running(Exec::Abortable) => {
                Cancelled::AbortBackend { context: block.sub.context }
            }
            Phase::Running(Exec::NonAbortable) => return Err(CancelError::InProgress),
        };
        block.decided = Some(Terminal::Cancelled);
        self.advance(slot);
        Ok(cancelled)
    }

    fn advance(&mut self, slot: usize) {
        let Some(mut block) = self.blocks[slot] else {
            return;
        };
        if let Some(terminal) = block.decided {
            if !block.published && (block.quiesced || !block.sub.uses_buffer) {
                block.published = true;
                self.reserved -= 1;
                if self.closing {
                    block.dropped = true;
                    self.stats.dropped += 1;
                } else {
                    self.cq.push_back(Completion {
                        request_id: block.id,
                        user_tag: block.sub.user_tag,
                        op: block.sub.op,
                        terminal,
                    });
                    if self.window.len() == self.capacity {
                        self.window.pop_front();
                    }
                    self.window.push_back((block.id, terminal));
                    self.stats.published += 1;
                }
            }
        }
        if block.quiesced && (block.published || block.dropped) {
            self.blocks[slot] = None;
            self.reclaimed.push_back(block.sub.context);
            self.stats.destroyed += 1;
        } else {
            self.blocks[slot] = Some(block);
        }
    }

    pub fn peek(&self, index: usize) -> Option<Completion> {
        self.cq.iter().nth(index).copied()
    }

    pub fn consume(&mut self, count: usize) -> usize {
        let mut consumed = 0;
        while consumed < count && self.cq.pop_front().is_some() {
            consumed += 1;
        }
        self.stats.consumed += consumed as u64;
        consumed
    }

    pub fn close(&mut self, mut abort: impl FnMut(u64, u64)) -> usize {
        if self.closing {
            return 0;
        }
        self.closing = true;
        let dropped = self.cq.len();
        self.cq.clear();
        self.stats.dropped += dropped as u64;

        let mut cancelled = 0;
        for slot in 0..self.blocks.len() {
            let Some(block) = self.blocks[slot].as_mut() else {
                continue;
            };
            if block.decided.is_none() {
                match block.phase {
                    Phase::Queued => {
                        block.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                    }
                    Phase::Running(Exec::Abortable) => {
                        block.decided = Some(Terminal::Cancelled);
                        cancelled += 1;
                        abort(block.sub.context, block.id);
                    }
                    Phase::Running(Exec::NonAbortable) => {}
                }
            }
            self.advance(slot);
        }
        cancelled
    }

    pub fn take_reclaimed(&mut self) -> Option<u64> {
        self.reclaimed.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn submission(tag: u64) -> Submission {
        Submission {
            op: 1,
            user_tag: tag,
            context: 100 + tag,
            uses_buffer: false,
        }
    }

    #[test]
    fn runtime_capacity_grows_past_previous_sixty_four_envelope() {
        let mut ring = RuntimeAsyncRing::new(128, 128).unwrap();
        for tag in 0..128 {
            ring.submit(submission(tag)).unwrap();
        }
        assert_eq!(ring.in_flight(), 128);
        assert_eq!(ring.credits(), 0);
        assert_eq!(ring.close(|_, _| {}), 128);
        assert!(ring.is_drained());
        assert_eq!(ring.reclaimed.len(), 128);
    }

    #[test]
    fn concurrent_callers_preserve_one_terminal_and_reclaim() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        const CALLERS: u64 = 8;
        const REQUESTS: u64 = 256;
        let ring = Arc::new(Mutex::new(
            RuntimeAsyncRing::new(2, (CALLERS * REQUESTS) as usize).unwrap(),
        ));
        let mut workers = Vec::new();
        for caller in 0..CALLERS {
            let ring = Arc::clone(&ring);
            workers.push(thread::spawn(move || {
                for index in 0..REQUESTS {
                    let context = caller * REQUESTS + index + 1;
                    let mut ring = ring.lock().unwrap();
                    let request = ring
                        .submit(Submission {
                            op: 9,
                            user_tag: context,
                            context,
                            uses_buffer: true,
                        })
                        .unwrap();
                    ring.start(request, Exec::Abortable).unwrap();
                    if index % 2 == 0 {
                        assert_eq!(
                            ring.cancel(request),
                            Ok(Cancelled::AbortBackend { context })
                        );
                        ring.quiesce(request).unwrap();
                    } else {
                        ring.finish(request, context as i64).unwrap();
                    }
                    assert_eq!(ring.take_reclaimed(), Some(context));
                    assert_eq!(ring.in_flight(), 0);
                    assert_eq!(ring.decided_unpublished(), 0);
                    assert_eq!(ring.consume(1), 1);
                    assert_eq!(ring.ready(), 0);
                    assert_eq!(ring.credits(), 2);
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        let ring = ring.lock().unwrap();
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.reserved(), 0);
        assert_eq!(ring.ready(), 0);
        assert_eq!(ring.credits(), ring.capacity());
    }

    #[test]
    fn device_backend_completion_waits_for_clean_reset_quiescence() {
        use crate::driver_host::{
            DeviceIdentity, DriverHostBroker, Needs, Policy, QuiesceProof,
        };

        let mut ring = RuntimeAsyncRing::new(2, 2).unwrap();
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let device = DeviceIdentity {
            identity: 0x1044,
            generation: 7,
        };
        broker.discover(device).unwrap();
        let host = broker.register_host().unwrap();
        let rights = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);
        let pass = broker
            .admit(host, device, rights, Policy::new(rights, 1, 1, 1))
            .unwrap();
        let driver_request = broker.begin_queue_work(pass, 1, 1, 1).unwrap();

        let context = 0x51;
        let request = ring
            .submit(Submission {
                op: 7,
                user_tag: 9,
                context,
                uses_buffer: true,
            })
            .unwrap();
        ring.start(request, Exec::Abortable).unwrap();
        assert_eq!(
            ring.cancel(request),
            Ok(Cancelled::AbortBackend { context })
        );
        assert_eq!(ring.decided_unpublished(), 1);
        assert_eq!(ring.ready(), 0);

        let unclean = QuiesceProof {
            dma_quiesced: false,
            irq_quiesced: true,
        };
        assert_eq!(
            broker.reset(host, unclean),
            Err(crate::driver_host::Error::NotQuiesced)
        );
        assert_eq!(broker.stats().pending_requests, 1);
        assert_eq!(ring.decided_unpublished(), 1);

        let reset = broker.reset(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(reset.cancelled, 1);
        assert_eq!(reset.revoked_passes, 1);
        assert_eq!(broker.cancel(driver_request), Err(crate::driver_host::Error::StaleRequest));
        ring.quiesce(request).unwrap();
        assert_eq!(ring.decided_unpublished(), 0);
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.ready(), 1);
        assert_eq!(ring.take_reclaimed(), Some(context));
        assert_eq!(
            ring.peek(0).map(|completion| {
                (completion.request_id, completion.user_tag, completion.terminal)
            }),
            Some((request, 9, Terminal::Cancelled))
        );
        assert_eq!(ring.consume(2), 1);
        assert_eq!(ring.consume(2), 0);
        assert_eq!(ring.quiesce(request), Err(ProgressError::NoSuchRequest));
        assert_eq!(broker.stats().pending_requests, 0);
        assert_eq!(broker.stats().active_passes, 0);
        assert_eq!(broker.stats().bound, 0);
    }

    #[test]
    fn device_backend_crash_quarantines_until_clean_recovery() {
        use crate::driver_host::{
            DeviceIdentity, DriverHostBroker, Needs, Policy, QuiesceProof,
        };

        let mut ring = RuntimeAsyncRing::new(2, 2).unwrap();
        let mut broker = DriverHostBroker::<1, 1, 1, 1>::new();
        let device = DeviceIdentity {
            identity: 0x1045,
            generation: 9,
        };
        broker.discover(device).unwrap();
        let host = broker.register_host().unwrap();
        let rights = Needs::DEVICE
            .union(Needs::MMIO)
            .union(Needs::MMIO_WRITE)
            .union(Needs::DMA)
            .union(Needs::DMA_WRITE)
            .union(Needs::IRQ);
        let pass = broker
            .admit(host, device, rights, Policy::new(rights, 1, 1, 1))
            .unwrap();
        let driver_request = broker.begin_queue_work(pass, 1, 1, 1).unwrap();

        let context = 0x52;
        let request = ring
            .submit(Submission {
                op: 8,
                user_tag: 10,
                context,
                uses_buffer: true,
            })
            .unwrap();
        ring.start(request, Exec::Abortable).unwrap();
        assert_eq!(
            ring.cancel(request),
            Ok(Cancelled::AbortBackend { context })
        );
        assert_eq!(ring.decided_unpublished(), 1);

        let crash = broker
            .crash(
                host,
                QuiesceProof {
                    dma_quiesced: false,
                    irq_quiesced: true,
                },
            )
            .unwrap();
        assert_eq!(crash.cancelled, 1);
        assert_eq!(crash.revoked_passes, 1);
        assert_eq!(crash.quarantined_devices, 1);
        assert_eq!(broker.stats().quarantined, 1);
        assert_eq!(
            broker.cancel(driver_request),
            Err(crate::driver_host::Error::StaleRequest)
        );
        assert_eq!(ring.decided_unpublished(), 1);
        assert_eq!(ring.ready(), 0);

        assert_eq!(
            broker.recover(
                host,
                QuiesceProof {
                    dma_quiesced: false,
                    irq_quiesced: true,
                }
            ),
            Err(crate::driver_host::Error::NotQuiesced)
        );
        let recovered = broker.recover(host, QuiesceProof::CLEAN).unwrap();
        assert_eq!(recovered.generation(), host.generation() + 1);
        assert_eq!(broker.stats().quarantined, 0);

        ring.quiesce(request).unwrap();
        assert_eq!(ring.decided_unpublished(), 0);
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.take_reclaimed(), Some(context));
        assert_eq!(
            ring.peek(0).map(|completion| completion.terminal),
            Some(Terminal::Cancelled)
        );
        assert_eq!(ring.consume(1), 1);
        assert_eq!(ring.quiesce(request), Err(ProgressError::NoSuchRequest));
    }

    #[test]
    fn fs_backend_cancel_waits_for_mapping_quiescence_and_reclaims_handle() {
        use crate::fs::{
            EntryName, FsCapabilities, FsContract, MountIdentity, NodeKind,
        };
        use crate::object::Rights;

        let mount = MountIdentity::new(0x5157, 0x0909, 1);
        let mut fs = FsContract::<4, 4>::format(
            mount,
            FsCapabilities::ALL,
            FsCapabilities::NONE,
        )
        .unwrap();
        let root = fs.root();
        let file = fs
            .create(
                root,
                EntryName::new(b"inflight").unwrap(),
                NodeKind::File,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap();
        let rights = Rights::READ.union(Rights::WRITE).union(Rights::MAP);
        let handle = fs.open(file, rights).unwrap();
        fs.write(handle, 4096).unwrap();
        let mapping = fs.map(handle, 0, 4096, true).unwrap();
        assert!(fs.mapping_valid(mapping));

        let context = handle.raw();
        let mut ring = RuntimeAsyncRing::new(2, 2).unwrap();
        let request = ring
            .submit(Submission {
                op: 31,
                user_tag: 7,
                context,
                uses_buffer: true,
            })
            .unwrap();
        ring.start(request, Exec::Abortable).unwrap();
        assert_eq!(
            ring.cancel(request),
            Ok(Cancelled::AbortBackend { context })
        );
        assert_eq!(ring.decided_unpublished(), 1);
        assert_eq!(ring.ready(), 0);
        assert_eq!(fs.live_handles(), 1);

        // Closing the real file handle invalidates the mapping and is the FS
        // backend's quiescence fact for the in-flight mapped operation.
        fs.close(handle).unwrap();
        assert!(!fs.mapping_valid(mapping));
        assert_eq!(fs.live_handles(), 0);
        assert_eq!(ring.decided_unpublished(), 1);

        ring.quiesce(request).unwrap();
        assert_eq!(ring.decided_unpublished(), 0);
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.take_reclaimed(), Some(context));
        assert_eq!(
            ring.peek(0).map(|completion| completion.terminal),
            Some(Terminal::Cancelled)
        );
        assert_eq!(ring.consume(2), 1);
        assert_eq!(ring.consume(2), 0);
        assert_eq!(ring.quiesce(request), Err(ProgressError::NoSuchRequest));
        assert_eq!(fs.live_handles(), 0);
    }

    #[test]
    #[cfg(feature = "network-dynamic")]
    fn net_backend_cancel_waits_for_socket_close_and_reclaims_queued_quota() {
        use crate::net4_runtime::{
            UdpAddress, UdpLimits, UdpQuota, UdpRights, UdpRuntimeError,
            UdpSocketRuntime,
        };

        let local = UdpAddress::new([10, 0, 4, 2], 4433);
        let remote = UdpAddress::new([10, 0, 4, 15], 49152);
        let initial_quota = UdpQuota::new(1, 2, 16);
        let mut runtime =
            UdpSocketRuntime::new(initial_quota, UdpLimits::new(1, 2, 16)).unwrap();
        let handle = runtime.bind(local, UdpRights::SERVICE).unwrap();
        runtime.receive(remote, local, b"payload").unwrap();
        assert_eq!(runtime.stats().queued_datagrams, 1);

        let context = u64::from(handle.slot()) << 32 | u64::from(handle.generation());
        let mut ring = RuntimeAsyncRing::new(2, 2).unwrap();
        let request = ring
            .submit(Submission {
                op: 32,
                user_tag: 8,
                context,
                uses_buffer: true,
            })
            .unwrap();
        ring.start(request, Exec::Abortable).unwrap();
        assert_eq!(
            ring.cancel(request),
            Ok(Cancelled::AbortBackend { context })
        );
        assert_eq!(ring.decided_unpublished(), 1);
        assert_eq!(ring.ready(), 0);

        runtime.close(handle).unwrap();
        assert_eq!(runtime.quota(), initial_quota);
        assert_eq!(runtime.stats().queued_datagrams, 0);
        assert_eq!(ring.decided_unpublished(), 1);

        ring.quiesce(request).unwrap();
        assert_eq!(ring.decided_unpublished(), 0);
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.take_reclaimed(), Some(context));
        assert_eq!(
            ring.peek(0).map(|completion| completion.terminal),
            Some(Terminal::Cancelled)
        );
        assert_eq!(ring.consume(2), 1);
        assert_eq!(ring.consume(2), 0);
        assert_eq!(ring.quiesce(request), Err(ProgressError::NoSuchRequest));
        let mut output = [0u8; 16];
        assert_eq!(
            runtime.recv(handle, &mut output),
            Err(UdpRuntimeError::Closed)
        );
        assert_eq!(runtime.close(handle), Err(UdpRuntimeError::Closed));
    }

    #[test]
    fn capacity_rejection_is_failure_atomic() {
        assert!(RuntimeAsyncRing::new(0, 4).is_none());
        assert!(RuntimeAsyncRing::new(5, 4).is_none());

        let mut ring = RuntimeAsyncRing::new(2, 8).unwrap();
        ring.submit(submission(1)).unwrap();
        ring.submit(submission(2)).unwrap();
        let before = (ring.credits(), ring.in_flight(), ring.next_id());
        let stats_before = ring.stats();
        assert_eq!(ring.submit(submission(3)), Err(SubmitError::CqFull));
        assert_eq!((ring.credits(), ring.in_flight(), ring.next_id()), before);
        let stats_after = ring.stats();
        assert_eq!(stats_after.rejected, stats_before.rejected + 1);
        assert_eq!(stats_after.accepted, stats_before.accepted);
        assert_eq!(stats_after.published, stats_before.published);
        assert_eq!(stats_after.consumed, stats_before.consumed);
        assert_eq!(stats_after.dropped, stats_before.dropped);
        assert_eq!(stats_after.destroyed, stats_before.destroyed);
    }

    #[test]
    fn gpu_backend_cancel_waits_for_reset_quiescence_and_rejects_stale_generation() {
        use crate::virtio_gpu::{
            GpuFrontendError, GpuPolicy, VirtioGpuBackend, CMD_RESOURCE_ATTACH_BACKING,
            CMD_RESOURCE_CREATE_2D, FORMAT_B8G8R8X8,
        };

        let mut gpu = VirtioGpuBackend::new(
            GpuPolicy::single_display(1024, 768, 4, 16 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        let mut response = [0u8; 512];

        let mut create = [0u8; 40];
        create[0..4].copy_from_slice(&CMD_RESOURCE_CREATE_2D.to_le_bytes());
        create[24..28].copy_from_slice(&1u32.to_le_bytes());
        create[28..32].copy_from_slice(&FORMAT_B8G8R8X8.to_le_bytes());
        create[32..36].copy_from_slice(&64u32.to_le_bytes());
        create[36..40].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(gpu.handle_command(&create, &mut response), Ok(24));

        let mut attach = [0u8; 48];
        attach[0..4].copy_from_slice(&CMD_RESOURCE_ATTACH_BACKING.to_le_bytes());
        attach[24..28].copy_from_slice(&1u32.to_le_bytes());
        attach[28..32].copy_from_slice(&1u32.to_le_bytes());
        attach[32..40].copy_from_slice(&0x20_0000u64.to_le_bytes());
        attach[40..44].copy_from_slice(&(64u32 * 64 * 4).to_le_bytes());
        assert_eq!(gpu.handle_command(&attach, &mut response), Ok(24));
        assert_eq!(gpu.resource_count(), 1);
        assert!(gpu.resident_bytes() > 0);

        let submitted_generation = gpu.generation();
        let context = u64::from(submitted_generation);
        let mut ring = RuntimeAsyncRing::new(2, 2).unwrap();
        let request = ring
            .submit(Submission {
                op: 41,
                user_tag: 17,
                context,
                uses_buffer: true,
            })
            .unwrap();
        ring.start(request, Exec::Abortable).unwrap();
        assert_eq!(
            ring.cancel(request),
            Ok(Cancelled::AbortBackend { context })
        );
        assert_eq!(ring.decided_unpublished(), 1);
        assert_eq!(ring.ready(), 0);
        assert!(gpu.validate_completion_generation(submitted_generation).is_ok());

        gpu.reset().unwrap();
        let reset_generation = gpu.generation();
        assert_ne!(reset_generation, submitted_generation);
        assert_eq!(gpu.resource_count(), 0);
        assert_eq!(gpu.resident_bytes(), 0);
        assert_eq!(
            gpu.validate_completion_generation(submitted_generation),
            Err(GpuFrontendError::StaleGeneration)
        );
        assert!(gpu.validate_completion_generation(reset_generation).is_ok());
        assert_eq!(ring.decided_unpublished(), 1);

        ring.quiesce(request).unwrap();
        assert_eq!(ring.decided_unpublished(), 0);
        assert_eq!(ring.in_flight(), 0);
        assert_eq!(ring.take_reclaimed(), Some(context));
        assert_eq!(
            ring.peek(0).map(|completion| completion.terminal),
            Some(Terminal::Cancelled)
        );
        assert_eq!(ring.consume(2), 1);
        assert_eq!(ring.consume(2), 0);
        assert_eq!(ring.quiesce(request), Err(ProgressError::NoSuchRequest));
        assert_eq!(ring.credits(), 2);
    }
}
