//! Bounded Binder context-manager and transaction compatibility driver.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use compat_core::syscall::CompatErrno;
use kernel_core::objtable::ObjId;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::proc;
use crate::sync::IrqSpinLock;

const BINDER_WRITE_READ_BYTES: usize = 48;
const BINDER_TRANSACTION_BYTES: usize = 64;
const BINDER_TRANSACTION_SG_BYTES: usize = 72;
const BINDER_READ_PACKET_BYTES: usize = 4 + BINDER_TRANSACTION_BYTES;
const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
const MAX_OFFSET_BYTES: usize = 4096;
const MAX_QUEUE: usize = 64;
const MAX_NODES: usize = 128;
const MAX_HANDLES: usize = 512;
const MAX_BINDER_THREADS: usize = 64;

const BINDER_TYPE_BINDER: u32 = 0x7362_2a85;
const BINDER_TYPE_WEAK_BINDER: u32 = 0x7762_2a85;
const BINDER_TYPE_HANDLE: u32 = 0x7368_2a85;
const BINDER_TYPE_WEAK_HANDLE: u32 = 0x7768_2a85;
const BINDER_TYPE_FD: u32 = 0x6664_2a85;
const FLAT_BINDER_OBJECT_BYTES: usize = 24;

const BC_TRANSACTION: u32 = 0x4040_6300;
const BC_REPLY: u32 = 0x4040_6301;
const BC_TRANSACTION_SG: u32 = 0x4048_6311;
const BC_REPLY_SG: u32 = 0x4048_6312;
const BC_FREE_BUFFER: u32 = 0x4008_6303;
const BC_INCREFS: u32 = 0x4004_6304;
const BC_ACQUIRE: u32 = 0x4004_6305;
const BC_RELEASE: u32 = 0x4004_6306;
const BC_DECREFS: u32 = 0x4004_6307;
const BC_REQUEST_DEATH_NOTIFICATION: u32 = 0x400c_630e;
const BC_CLEAR_DEATH_NOTIFICATION: u32 = 0x400c_630f;
const BC_DEAD_BINDER_DONE: u32 = 0x4008_6310;
const BC_ENTER_LOOPER: u32 = 0x630c;
const BC_EXIT_LOOPER: u32 = 0x630d;
const BC_REGISTER_LOOPER: u32 = 0x630b;

const BR_TRANSACTION: u32 = 0x8040_7202;
const BR_REPLY: u32 = 0x8040_7203;
const BR_DEAD_REPLY: u32 = 0x7205;
const BR_TRANSACTION_COMPLETE: u32 = 0x7206;
const BR_OK: u32 = 0x7201;
const BR_FAILED_REPLY: u32 = 0x7211;
const BR_FROZEN_REPLY: u32 = 0x7212;
const BR_ONEWAY_SPAM_SUSPECT: u32 = 0x7213;
const BR_TRANSACTION_PENDING_FROZEN: u32 = 0x7214;
const BR_SPAWN_LOOPER: u32 = 0x720d;
const BR_DEAD_BINDER: u32 = 0x8008_720f;
const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8008_7210;
const TF_ONE_WAY: u32 = 0x01;
const ONEWAY_SPAM_SUSPECT_THRESHOLD: u32 = 32;

enum QueuedCommand {
    Complete,
    ReplyError {
        command: u32,
    },
    SpawnLooper,
    DeathNotification {
        command: u32,
        cookie: u64,
    },
    Transaction {
        command: u32,
        sender: ObjId,
        code: u32,
        flags: u32,
        data: Vec<u8>,
        offsets: Vec<u8>,
    },
}

struct ActiveTransaction {
    target: ObjId,
    sender: ObjId,
}

struct TransactionBuffer {
    process: ObjId,
    address: u64,
    length: usize,
}

#[derive(Clone, Copy)]
struct ExtendedError {
    process: ObjId,
    tid: u32,
    id: u32,
    command: u32,
    param: i32,
}

#[derive(Clone, Copy)]
struct FrozenProcess {
    process: ObjId,
    sync_recv: u32,
    async_recv: u32,
}

#[derive(Clone, Copy)]
struct SpamSample {
    sender: ObjId,
    target: ObjId,
    count: u32,
}

#[derive(Clone, Copy)]
struct Node {
    id: u64,
    owner: ObjId,
    pointer: u64,
    cookie: u64,
    strong_refs: u32,
    weak_refs: u32,
    dead: bool,
}

#[derive(Clone, Copy)]
struct LocalHandle {
    recipient: ObjId,
    node: u64,
    handle: u32,
}

#[derive(Clone, Copy)]
struct DeathRequest {
    recipient: ObjId,
    node: u64,
    cookie: u64,
}

#[derive(Clone, Copy)]
struct BinderThread {
    process: ObjId,
    task: crate::task::TaskId,
    tid: u32,
    pool_member: bool,
}

struct State {
    context_manager: Option<ObjId>,
    queue: VecDeque<(ObjId, QueuedCommand)>,
    active: Vec<ActiveTransaction>,
    buffers: Vec<TransactionBuffer>,
    nodes: Vec<Node>,
    handles: Vec<LocalHandle>,
    next_node: u64,
    next_handle: u32,
    death_requests: Vec<DeathRequest>,
    threads: Vec<BinderThread>,
    spawn_pending: Vec<ObjId>,
    extended_errors: Vec<ExtendedError>,
    oneway_spam: Vec<ObjId>,
    frozen_processes: Vec<FrozenProcess>,
    spam_samples: Vec<SpamSample>,
    next_error_id: u32,
}

impl State {
    const fn new() -> Self {
        Self {
            context_manager: None,
            queue: VecDeque::new(),
            active: Vec::new(),
            buffers: Vec::new(),
            nodes: Vec::new(),
            handles: Vec::new(),
            next_node: 1,
            next_handle: 1,
            death_requests: Vec::new(),
            threads: Vec::new(),
            spawn_pending: Vec::new(),
            extended_errors: Vec::new(),
            oneway_spam: Vec::new(),
            frozen_processes: Vec::new(),
            spam_samples: Vec::new(),
            next_error_id: 1,
        }
    }
}

static BINDER: IrqSpinLock<State> =
    IrqSpinLock::ranked(crate::lockorder::BINDER, State::new());

pub(crate) fn set_context_manager(pid: ObjId) -> bool {
    let current = BINDER.lock().context_manager;
    if let Some(owner) = current {
        if owner != pid && proc::state(owner) == Some(proc::ProcState::Running) {
            return false;
        }
    }
    let mut state = BINDER.lock();
    if state
        .context_manager
        .is_some_and(|owner| owner != pid && Some(owner) != current)
    {
        return false;
    }
    state.context_manager = Some(pid);
    true
}

/// Installs the legacy context manager from an extended flat binder object.
/// 从扩展 flat binder object 安装 legacy context manager。
pub(crate) fn set_context_manager_ext(
    pid: ObjId,
    pointer: u64,
    cookie: u64,
) -> bool {
    if pointer == 0 {
        return false;
    }
    let mut state = BINDER.lock();
    if state
        .context_manager
        .is_some_and(|owner| owner != pid && proc::state(owner) == Some(proc::ProcState::Running))
    {
        return false;
    }
    if state.nodes.len() >= MAX_NODES {
        return false;
    }
    if state.nodes.iter().all(|node| node.owner != pid || node.pointer != pointer) {
        let id = state.next_node;
        let Some(next) = id.checked_add(1) else {
            return false;
        };
        state.next_node = next;
        state.nodes.push(Node {
            id,
            owner: pid,
            pointer,
            cookie,
            strong_refs: 1,
            weak_refs: 0,
            dead: false,
        });
    }
    state.context_manager = Some(pid);
    true
}

/// Releases every Binder node, local handle and queued state owned by one
/// compatibility process. Called after its final Linux thread exits.
pub(crate) fn release_process(pid: ObjId) {
    let mut state = BINDER.lock();
    if state.context_manager == Some(pid) {
        state.context_manager = None;
    }
    let mut dead_nodes = [0u64; MAX_NODES];
    let mut dead_count = 0usize;
    for node in state
        .nodes
        .iter()
        .filter(|node| node.owner == pid && !node.dead)
    {
        dead_nodes[dead_count] = node.id;
        dead_count += 1;
    }
    let notifications = state
        .death_requests
        .iter()
        .filter(|request| dead_nodes[..dead_count].contains(&request.node))
        .count();
    let mut dead_replies = Vec::new();
    if dead_replies
        .try_reserve(state.active.len().saturating_mul(2))
        .is_err()
    {
        dead_replies.clear();
    } else {
        for active in &state.active {
            if active.target == pid && proc::state(active.sender) == Some(proc::ProcState::Running) {
                dead_replies.push(active.sender);
            }
            if active.sender == pid && proc::state(active.target) == Some(proc::ProcState::Running) {
                dead_replies.push(active.target);
            }
        }
    }
    if state
        .queue
        .try_reserve(notifications.saturating_add(dead_replies.len()))
        .is_ok()
    {
        for node in dead_nodes[..dead_count].iter().copied() {
            for index in 0..state.death_requests.len() {
                let request = state.death_requests[index];
                if request.node == node {
                    state.queue.push_back((
                        request.recipient,
                        QueuedCommand::DeathNotification {
                            command: BR_DEAD_BINDER,
                            cookie: request.cookie,
                        },
                    ));
                }
            }
        }
        for recipient in dead_replies {
            state.queue.push_back((
                recipient,
                QueuedCommand::ReplyError {
                    command: BR_DEAD_REPLY,
                },
            ));
        }
    }
    // Keep dead node identities as tombstones. Existing remote handles must
    // continue resolving to the dead owner so transactions return BR_DEAD_REPLY
    // instead of being confused with an unknown handle (BR_FAILED_REPLY).
    for node in state.nodes.iter_mut().filter(|node| node.owner == pid) {
        node.strong_refs = 0;
        node.weak_refs = 0;
        node.dead = true;
    }
    state.handles.retain(|binding| binding.recipient != pid);
    state
        .death_requests
        .retain(|request| request.recipient != pid);
    let mut referenced_nodes = Vec::new();
    if referenced_nodes
        .try_reserve(state.handles.len().saturating_add(state.death_requests.len()))
        .is_ok()
    {
        referenced_nodes.extend(state.handles.iter().map(|handle| handle.node));
        referenced_nodes.extend(state.death_requests.iter().map(|request| request.node));
        state.nodes.retain(|node| !node.dead || referenced_nodes.contains(&node.id));
    }
    state.threads.retain(|thread| thread.process != pid);
    state.spawn_pending.retain(|process| *process != pid);
    state
        .extended_errors
        .retain(|error| error.process != pid);
    state.oneway_spam.retain(|process| *process != pid);
    state
        .frozen_processes
        .retain(|frozen| frozen.process != pid);
    state
        .spam_samples
        .retain(|sample| sample.sender != pid && sample.target != pid);
    state.active.retain(|active| active.target != pid && active.sender != pid);
    state.buffers.retain(|buffer| buffer.process != pid);
    state.queue.retain(|(target, _)| *target != pid);
    state.nodes.shrink_to_fit();
    state.handles.shrink_to_fit();
    state.death_requests.shrink_to_fit();
    state.threads.shrink_to_fit();
    state.spawn_pending.shrink_to_fit();
    state.extended_errors.shrink_to_fit();
    state.oneway_spam.shrink_to_fit();
    state.frozen_processes.shrink_to_fit();
    state.spam_samples.shrink_to_fit();
    state.active.shrink_to_fit();
    state.buffers.shrink_to_fit();
    state.queue.shrink_to_fit();
}

pub(crate) fn thread_exit(pid: ObjId) {
    let Some(tid) = crate::linux_abi::current_linux_tid(pid) else {
        return;
    };
    release_thread(pid, tid);
}

pub(crate) fn release_thread(pid: ObjId, tid: u32) {
    let mut state = BINDER.lock();
    state
        .threads
        .retain(|thread| thread.process != pid || thread.tid != tid);
}

/// Returns one node in pointer-cursor order for `BINDER_GET_NODE_DEBUG_INFO`.
pub(crate) fn get_node_debug_info(_pid: ObjId, request: u64) -> Result<u64, CompatErrno> {
    const INFO_BYTES: usize = 24;
    let mut input = [0u8; INFO_BYTES];
    copy_from_user(&mut input, request, INFO_BYTES).map_err(|_| CompatErrno::Fault)?;
    let cursor = u64::from_le_bytes(input[0..8].try_into().unwrap());
    let state = BINDER.lock();
    let next = if cursor == 0 {
        state.nodes.iter().min_by_key(|node| node.id)
    } else {
        let current = state
            .nodes
            .iter()
            .find(|node| node.pointer == cursor)
            .ok_or(CompatErrno::NoEntry)?;
        state
            .nodes
            .iter()
            .filter(|node| node.id > current.id)
            .min_by_key(|node| node.id)
    };
    let mut output = [0u8; INFO_BYTES];
    if let Some(node) = next {
        output[0..8].copy_from_slice(&node.pointer.to_le_bytes());
        output[8..16].copy_from_slice(&node.cookie.to_le_bytes());
        output[16..20].copy_from_slice(&u32::from(node.strong_refs != 0).to_le_bytes());
        output[20..24].copy_from_slice(&u32::from(node.weak_refs != 0).to_le_bytes());
    }
    drop(state);
    copy_to_user(request, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Returns strong/weak counts for one local Binder handle.
pub(crate) fn get_node_info_for_ref(pid: ObjId, request: u64) -> Result<u64, CompatErrno> {
    const INFO_BYTES: usize = 24;
    let mut input = [0u8; INFO_BYTES];
    copy_from_user(&mut input, request, INFO_BYTES).map_err(|_| CompatErrno::Fault)?;
    let handle = u32::from_le_bytes(input[0..4].try_into().unwrap());
    let state = BINDER.lock();
    let node_id = state
        .handles
        .iter()
        .find(|binding| binding.recipient == pid && binding.handle == handle)
        .map(|binding| binding.node)
        .ok_or(CompatErrno::NoEntry)?;
    let node = state
        .nodes
        .iter()
        .find(|node| node.id == node_id)
        .ok_or(CompatErrno::NoEntry)?;
    let mut output = [0u8; INFO_BYTES];
    output[0..4].copy_from_slice(&handle.to_le_bytes());
    output[4..8].copy_from_slice(&node.strong_refs.to_le_bytes());
    output[8..12].copy_from_slice(&node.weak_refs.to_le_bytes());
    drop(state);
    copy_to_user(request, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

/// Stores the process-wide one-way spam detection setting. This slice retains
/// the UAPI state; heuristic suspect reporting remains a separate behavior.
pub(crate) fn set_oneway_spam_detection(pid: ObjId, enabled: bool) -> bool {
    let mut state = BINDER.lock();
    let index = state.oneway_spam.iter().position(|process| *process == pid);
    if enabled {
        if index.is_none() {
            if state.oneway_spam.try_reserve(1).is_err() {
                return false;
            }
            state.oneway_spam.push(pid);
        }
    } else if let Some(index) = index {
        state.oneway_spam.swap_remove(index);
        state.spam_samples.retain(|sample| sample.sender != pid);
    }
    true
}

/// Updates Binder-level process freeze state. Frozen processes remain
/// schedulable, but incoming transactions obey the Binder frozen protocol.
pub(crate) fn set_frozen(
    requester: ObjId,
    target_pid: u32,
    enable: bool,
) -> Result<(), CompatErrno> {
    let target = proc::linux_process_for_pid(target_pid).ok_or(CompatErrno::NoProcess)?;
    if target != requester && proc::app(target) != proc::app(requester) {
        return Err(CompatErrno::Perm);
    }
    if proc::state(target) != Some(proc::ProcState::Running) {
        return Err(CompatErrno::NoProcess);
    }
    let mut state = BINDER.lock();
    let index = state
        .frozen_processes
        .iter()
        .position(|frozen| frozen.process == target);
    if enable {
        if index.is_none() {
            state
                .frozen_processes
                .try_reserve(1)
                .map_err(|_| CompatErrno::NoMemory)?;
            state.frozen_processes.push(FrozenProcess {
                process: target,
                sync_recv: 0,
                async_recv: 0,
            });
        }
    } else {
        let index = index.ok_or(CompatErrno::Invalid)?;
        state.frozen_processes.remove(index);
    }
    let wake = state
        .threads
        .iter()
        .filter(|thread| thread.process == target)
        .map(|thread| thread.task)
        .collect::<Vec<_>>();
    drop(state);
    for task in wake {
        crate::sched::wake(task);
    }
    Ok(())
}

/// Returns and clears frozen-transaction counters for one process.
pub(crate) fn get_frozen_status(
    _requester: ObjId,
    target_pid: u32,
) -> Result<(u32, u32, u32), CompatErrno> {
    let target = proc::linux_process_for_pid(target_pid).ok_or(CompatErrno::NoProcess)?;
    let mut state = BINDER.lock();
    let frozen = state
        .frozen_processes
        .iter_mut()
        .find(|frozen| frozen.process == target)
        .ok_or(CompatErrno::Invalid)?;
    let (sync_recv, async_recv) = (frozen.sync_recv, frozen.async_recv);
    frozen.sync_recv = 0;
    frozen.async_recv = 0;
    Ok((target_pid, sync_recv, async_recv))
}

fn process_is_frozen(process: ObjId) -> bool {
    BINDER
        .lock()
        .frozen_processes
        .iter()
        .any(|frozen| frozen.process == process)
}

fn note_frozen_transaction(target: ObjId, one_way: bool) {
    let mut state = BINDER.lock();
    if let Some(frozen) = state
        .frozen_processes
        .iter_mut()
        .find(|frozen| frozen.process == target)
    {
        if one_way {
            frozen.async_recv = frozen.async_recv.saturating_add(1);
        } else {
            frozen.sync_recv |= 0x3;
        }
    }
}

/// Advances the bounded one-way spam heuristic for one sender/target pair.
fn note_oneway_spam(state: &mut State, sender: ObjId, target: ObjId) -> bool {
    if !state.oneway_spam.contains(&sender) {
        return false;
    }
    if let Some(sample) = state
        .spam_samples
        .iter_mut()
        .find(|sample| sample.sender == sender && sample.target == target)
    {
        sample.count = sample.count.saturating_add(1);
        if sample.count >= ONEWAY_SPAM_SUSPECT_THRESHOLD {
            sample.count = 0;
            return true;
        }
        return false;
    }
    if state.spam_samples.try_reserve(1).is_err() {
        return false;
    }
    state.spam_samples.push(SpamSample {
        sender,
        target,
        count: 1,
    });
    false
}

/// Returns and clears the calling thread's extended transaction error.
pub(crate) fn get_extended_error(pid: ObjId, address: u64) -> Result<u64, CompatErrno> {
    let tid = crate::linux_abi::current_linux_tid(pid).ok_or(CompatErrno::NoSys)?;
    let error = {
        let mut state = BINDER.lock();
        state
            .extended_errors
            .iter()
            .position(|error| error.process == pid && error.tid == tid)
            .map(|index| state.extended_errors.remove(index))
    };
    let mut output = [0u8; 12];
    let (id, command, param) = error
        .map(|error| (error.id, error.command, error.param))
        .unwrap_or((0, BR_OK, 0));
    output[0..4].copy_from_slice(&id.to_le_bytes());
    output[4..8].copy_from_slice(&command.to_le_bytes());
    output[8..12].copy_from_slice(&param.to_le_bytes());
    copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

pub(crate) fn write_read(pid: ObjId, fd: u32, args: [u64; 6]) -> Result<u64, CompatErrno> {
    let request_pointer = args[2];
    let mut request = [0u8; BINDER_WRITE_READ_BYTES];
    copy_from_user(&mut request, request_pointer, BINDER_WRITE_READ_BYTES)
        .map_err(|_| CompatErrno::Fault)?;
    let write_size = usize::try_from(u64::from_le_bytes(request[0..8].try_into().unwrap()))
        .map_err(|_| CompatErrno::Invalid)?;
    let write_buffer = u64::from_le_bytes(request[16..24].try_into().unwrap());
    let read_size = usize::try_from(u64::from_le_bytes(request[24..32].try_into().unwrap()))
        .map_err(|_| CompatErrno::Invalid)?;
    let read_buffer = u64::from_le_bytes(request[40..48].try_into().unwrap());
    if write_size > MAX_TRANSACTION_BYTES + MAX_OFFSET_BYTES + 1024
        || read_size > MAX_TRANSACTION_BYTES + MAX_OFFSET_BYTES
    {
        return Err(CompatErrno::Invalid);
    }
    let write_consumed = process_write(pid, write_buffer, write_size)?;
    copy_to_user(
        request_pointer + 8,
        &(write_consumed as u64).to_le_bytes(),
        8,
    )
    .map_err(|_| CompatErrno::Fault)?;

    let nonblocking =
        proc::linux_fd_status_flags(pid, fd).ok_or(CompatErrno::BadFd)? & 0x800 != 0;
    let read_consumed = if read_size < 4 {
        0
    } else {
        loop {
            let queued = {
                let mut state = BINDER.lock();
                let frozen = state
                    .frozen_processes
                    .iter()
                    .any(|frozen| frozen.process == pid);
                state
                    .queue
                    .iter()
                    .position(|(target, command)| {
                        *target == pid
                            && (!frozen
                                || !matches!(command, QueuedCommand::Transaction { .. }))
                    })
                    .and_then(|index| state.queue.remove(index))
                    .map(|(_, command)| command)
            };
            if let Some(command) = queued {
                break deliver(pid, read_buffer, read_size, command)?;
            }
            if nonblocking {
                break 0;
            }
            if proc::current_exiting() || crate::linux_abi::current_signal_pending(pid) {
                return Err(CompatErrno::Interrupted);
            }
            crate::sched::pause();
        }
    };
    copy_to_user(
        request_pointer + 32,
        &(read_consumed as u64).to_le_bytes(),
        8,
    )
    .map_err(|_| CompatErrno::Fault)?;
    Ok(0)
}

fn process_write(pid: ObjId, address: u64, size: usize) -> Result<usize, CompatErrno> {
    if size == 0 {
        return Ok(0);
    }
    let mut bytes = alloc::vec![0u8; size];
    copy_from_user(&mut bytes, address, size).map_err(|_| CompatErrno::Fault)?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        if bytes.len() - offset < 4 {
            return Err(CompatErrno::Invalid);
        }
        let command = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        match command {
            BC_TRANSACTION | BC_REPLY => {
                if bytes.len() - offset < 4 + BINDER_TRANSACTION_BYTES {
                    return Err(CompatErrno::Invalid);
                }
                enqueue_transaction(pid, command, &bytes[offset + 4..offset + 68])?;
                offset += 68;
            }
            BC_TRANSACTION_SG | BC_REPLY_SG => {
                if bytes.len() - offset < 4 + BINDER_TRANSACTION_SG_BYTES {
                    return Err(CompatErrno::Invalid);
                }
                let buffers_size = u64::from_le_bytes(
                    bytes[offset + 68..offset + 76].try_into().unwrap(),
                );
                let data_size = u64::from_le_bytes(
                    bytes[offset + 36..offset + 44].try_into().unwrap(),
                );
                let offsets_size = u64::from_le_bytes(
                    bytes[offset + 44..offset + 52].try_into().unwrap(),
                );
                let required = data_size
                    .checked_add(offsets_size)
                    .ok_or(CompatErrno::Invalid)?;
                if buffers_size < required
                    || buffers_size > (MAX_TRANSACTION_BYTES + MAX_OFFSET_BYTES) as u64
                {
                    return Err(CompatErrno::Invalid);
                }
                let normal_command = if command == BC_TRANSACTION_SG {
                    BC_TRANSACTION
                } else {
                    BC_REPLY
                };
                enqueue_transaction(pid, normal_command, &bytes[offset + 4..offset + 68])?;
                offset += 76;
            }
            BC_FREE_BUFFER => {
                if bytes.len() - offset < 12 {
                    return Err(CompatErrno::Invalid);
                }
                let pointer = u64::from_le_bytes(bytes[offset + 4..offset + 12].try_into().unwrap());
                let length = {
                    let mut state = BINDER.lock();
                    let index = state
                        .buffers
                        .iter()
                        .position(|buffer| buffer.process == pid && buffer.address == pointer)
                        .ok_or(CompatErrno::Invalid)?;
                    state.buffers.remove(index).length
                };
                if !proc::linux_free_transaction_buffer(pid, pointer, length) {
                    return Err(CompatErrno::Invalid);
                }
                offset += 12;
            }
            BC_INCREFS | BC_ACQUIRE | BC_RELEASE | BC_DECREFS => {
                if bytes.len() - offset < 8 {
                    return Err(CompatErrno::Invalid);
                }
                let handle =
                    u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
                process_reference(pid, command, handle)?;
                offset += 8;
            }
            BC_REQUEST_DEATH_NOTIFICATION | BC_CLEAR_DEATH_NOTIFICATION => {
                if bytes.len() - offset < 16 {
                    return Err(CompatErrno::Invalid);
                }
                let handle =
                    u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
                let cookie = u64::from_le_bytes(
                    bytes[offset + 8..offset + 16].try_into().unwrap(),
                );
                if command == BC_REQUEST_DEATH_NOTIFICATION {
                    request_death(pid, handle, cookie)?;
                } else {
                    clear_death(pid, handle, cookie)?;
                }
                offset += 16;
            }
            BC_DEAD_BINDER_DONE => {
                if bytes.len() - offset < 12 {
                    return Err(CompatErrno::Invalid);
                }
                let cookie = u64::from_le_bytes(
                    bytes[offset + 4..offset + 12].try_into().unwrap(),
                );
                BINDER
                    .lock()
                    .death_requests
                    .retain(|request| {
                        request.recipient != pid || request.cookie != cookie
                    });
                offset += 12;
            }
            BC_ENTER_LOOPER | BC_EXIT_LOOPER | BC_REGISTER_LOOPER => {
                let tid = crate::linux_abi::current_linux_tid(pid)
                    .ok_or(CompatErrno::NoSys)?;
                let (task, _) = crate::sched::current();
                update_looper(pid, task, tid, command)?;
                offset += 4;
            }
            _ => return Err(CompatErrno::NoSys),
        }
    }
    Ok(offset)
}

fn update_looper(
    pid: ObjId,
    task: crate::task::TaskId,
    tid: u32,
    command: u32,
) -> Result<(), CompatErrno> {
    let mut state = BINDER.lock();
    let existing = state
        .threads
        .iter()
        .position(|thread| thread.process == pid && thread.tid == tid);
    if command == BC_EXIT_LOOPER {
        if let Some(index) = existing {
            state.threads.remove(index);
        }
        crate::kprintln!("[JSR-BINDER] looper-exit pid={} tid={}", pid.raw(), tid);
        return Ok(());
    }
    let pool_member = command == BC_REGISTER_LOOPER;
    if let Some(index) = existing {
        state.threads[index].pool_member |= pool_member;
        state.threads[index].task = task;
    } else {
        if state.threads.len() >= MAX_BINDER_THREADS {
            return Err(CompatErrno::NoSpace);
        }
        state
            .threads
            .try_reserve(1)
            .map_err(|_| CompatErrno::NoMemory)?;
        state.threads.push(BinderThread {
            process: pid,
            task,
            tid,
            pool_member,
        });
    }
    if pool_member {
        state.spawn_pending.retain(|process| *process != pid);
        state.queue.retain(|(target, command)| {
            *target != pid || !matches!(command, QueuedCommand::SpawnLooper)
        });
    }
    crate::kprintln!(
        "[JSR-BINDER] looper-register pid={} tid={} pool={} threads={}",
        pid.raw(),
        tid,
        pool_member,
        state.threads.len()
    );
    Ok(())
}

fn process_reference(
    recipient: ObjId,
    command: u32,
    handle: u32,
) -> Result<(), CompatErrno> {
    let mut state = BINDER.lock();
    let node_id = state
        .handles
        .iter()
        .find(|binding| binding.recipient == recipient && binding.handle == handle)
        .map(|binding| binding.node)
        .ok_or(CompatErrno::NoEntry)?;
    let node = state
        .nodes
        .iter_mut()
        .find(|node| node.id == node_id)
        .ok_or(CompatErrno::NoEntry)?;
    match command {
        BC_ACQUIRE => {
            node.strong_refs = node.strong_refs.checked_add(1).ok_or(CompatErrno::NoSpace)?
        }
        BC_RELEASE => {
            node.strong_refs = node.strong_refs.checked_sub(1).ok_or(CompatErrno::Invalid)?
        }
        BC_INCREFS => {
            node.weak_refs = node.weak_refs.checked_add(1).ok_or(CompatErrno::NoSpace)?
        }
        BC_DECREFS => {
            node.weak_refs = node.weak_refs.checked_sub(1).ok_or(CompatErrno::Invalid)?
        }
        _ => return Err(CompatErrno::Invalid),
    }
    Ok(())
}

fn request_death(recipient: ObjId, handle: u32, cookie: u64) -> Result<(), CompatErrno> {
    let mut state = BINDER.lock();
    let node = state
        .handles
        .iter()
        .find(|binding| binding.recipient == recipient && binding.handle == handle)
        .map(|binding| binding.node)
        .ok_or(CompatErrno::NoEntry)?;
    state
        .death_requests
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    if let Some(request) = state
        .death_requests
        .iter_mut()
        .find(|request| request.recipient == recipient && request.node == node)
    {
        request.cookie = cookie;
    } else {
        state.death_requests.push(DeathRequest {
            recipient,
            node,
            cookie,
        });
    }
    Ok(())
}

fn clear_death(recipient: ObjId, handle: u32, cookie: u64) -> Result<(), CompatErrno> {
    let mut state = BINDER.lock();
    let node = state
        .handles
        .iter()
        .find(|binding| binding.recipient == recipient && binding.handle == handle)
        .map(|binding| binding.node)
        .ok_or(CompatErrno::NoEntry)?;
    let index = state
        .death_requests
        .iter()
        .position(|request| {
            request.recipient == recipient && request.node == node && request.cookie == cookie
        })
        .ok_or(CompatErrno::NoEntry)?;
    state.queue.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
    state.death_requests.remove(index);
    state.queue.push_back((
        recipient,
        QueuedCommand::DeathNotification {
            command: BR_CLEAR_DEATH_NOTIFICATION_DONE,
            cookie,
        },
    ));
    Ok(())
}

fn resolve_transaction_target(pid: ObjId, handle: u32) -> Result<ObjId, CompatErrno> {
    let state = BINDER.lock();
    if handle == 0 {
        return state.context_manager.ok_or(CompatErrno::NoEntry);
    }
    let binding = state
        .handles
        .iter()
        .find(|binding| binding.recipient == pid && binding.handle == handle)
        .ok_or(CompatErrno::NoEntry)?;
    state
        .nodes
        .iter()
        .find(|node| node.id == binding.node)
        .map(|node| node.owner)
        .ok_or(CompatErrno::NoEntry)
}

/// Queues the asynchronous completion sequence for a transaction that failed
/// before it could be delivered to the peer.
fn queue_reply_error(
    pid: ObjId,
    command: u32,
    param: CompatErrno,
) -> Result<(), CompatErrno> {
    let mut state = BINDER.lock();
    if state.queue.len().saturating_add(2) > MAX_QUEUE {
        return Err(CompatErrno::TryAgain);
    }
    state
        .queue
        .try_reserve(2)
        .map_err(|_| CompatErrno::NoMemory)?;
    state
        .extended_errors
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let tid = crate::linux_abi::current_linux_tid(pid).unwrap_or(0);
    state
        .extended_errors
        .retain(|error| error.process != pid || error.tid != tid);
    let id = state.next_error_id;
    state.next_error_id = state.next_error_id.wrapping_add(1).max(1);
    state.extended_errors.push(ExtendedError {
        process: pid,
        tid,
        id,
        command,
        param: -(param as i32),
    });
    state.queue.push_back((pid, QueuedCommand::Complete));
    state.queue.push_back((pid, QueuedCommand::ReplyError { command }));
    crate::kprintln!(
        "[JSR-BINDER] reply-error-queued recipient={} command={:#x} queue={}",
        pid.raw(),
        command,
        state.queue.len()
    );
    Ok(())
}

/// Translates flat binder objects in one transaction. Binder definitions become
/// receiver-local handles; outgoing handles are translated back to the node
/// owner's binder object.
fn translate_objects(
    sender: ObjId,
    recipient: ObjId,
    data: &mut [u8],
    offsets: &[u8],
) -> Result<(), CompatErrno> {
    if offsets.is_empty() {
        return Ok(());
    }
    if offsets.len() % 8 != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve(offsets.len() / 8)
        .map_err(|_| CompatErrno::NoMemory)?;
    for chunk in offsets.chunks_exact(8) {
        let offset = usize::try_from(u64::from_le_bytes(chunk.try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
        let end = offset
            .checked_add(FLAT_BINDER_OBJECT_BYTES)
            .ok_or(CompatErrno::Invalid)?;
        let object = data.get(offset..end).ok_or(CompatErrno::Invalid)?;
        let object_type = u32::from_le_bytes(object[..4].try_into().unwrap());
        let value = u64::from_le_bytes(object[8..16].try_into().unwrap());
        let cookie = u64::from_le_bytes(object[16..24].try_into().unwrap());
        if !matches!(
            object_type,
            BINDER_TYPE_BINDER
                | BINDER_TYPE_WEAK_BINDER
                | BINDER_TYPE_HANDLE
                | BINDER_TYPE_WEAK_HANDLE
                | BINDER_TYPE_FD
        ) {
            return Err(CompatErrno::NoSys);
        }
        objects.push((offset, value, cookie, object_type));
    }

    let mut installed_fds = Vec::new();
    installed_fds
        .try_reserve(objects.len())
        .map_err(|_| CompatErrno::NoMemory)?;
    for (offset, value, _cookie, object_type) in &objects {
        if *object_type != BINDER_TYPE_FD {
            continue;
        }
        let fd = u32::try_from(*value).map_err(|_| CompatErrno::Invalid)?;
        let transfer = match proc::linux_capture_fd_transfer(sender, fd) {
            Ok(transfer) => transfer,
            Err(_) => {
                for installed in installed_fds {
                    let _ = proc::linux_close_fd(recipient, installed);
                }
                return Err(CompatErrno::BadFd);
            }
        };
        match proc::linux_install_fd_transfer(recipient, transfer, false) {
            Ok(installed) => {
                let object = &mut data[*offset..*offset + FLAT_BINDER_OBJECT_BYTES];
                object[8..12].copy_from_slice(&installed.to_le_bytes());
                object[12..16].fill(0);
                installed_fds.push(installed);
            }
            Err(_) => {
                for installed in installed_fds {
                    let _ = proc::linux_close_fd(recipient, installed);
                }
                return Err(CompatErrno::NoSpace);
            }
        }
    }

    let result = (|| {
        let mut state = BINDER.lock();
        state
            .nodes
            .try_reserve(objects.len())
            .map_err(|_| CompatErrno::NoMemory)?;
        state
            .handles
            .try_reserve(objects.len())
            .map_err(|_| CompatErrno::NoMemory)?;
        for (offset, value, cookie, object_type) in objects {
        if object_type == BINDER_TYPE_FD {
            continue;
        }
        let weak = matches!(
            object_type,
            BINDER_TYPE_WEAK_BINDER | BINDER_TYPE_WEAK_HANDLE
        );
        let node_id = match object_type {
            BINDER_TYPE_BINDER | BINDER_TYPE_WEAK_BINDER => {
                if let Some(node) = state
                    .nodes
                    .iter()
                    .find(|node| node.owner == sender && node.pointer == value)
                {
                    node.id
                } else {
                    if state.nodes.len() >= MAX_NODES {
                        return Err(CompatErrno::NoSpace);
                    }
                    let id = state.next_node;
                    state.next_node = id.checked_add(1).ok_or(CompatErrno::NoSpace)?;
                    state.nodes.push(Node {
                        id,
                        owner: sender,
                        pointer: value,
                        cookie,
                        strong_refs: u32::from(!weak),
                        weak_refs: u32::from(weak),
                        dead: false,
                    });
                    id
                }
            }
            BINDER_TYPE_HANDLE | BINDER_TYPE_WEAK_HANDLE => {
                let handle = u32::try_from(value).map_err(|_| CompatErrno::Invalid)?;
                let binding = state
                    .handles
                    .iter()
                    .find(|binding| {
                        binding.recipient == sender && binding.handle == handle
                    })
                    .ok_or(CompatErrno::NoEntry)?;
                binding.node
            }
            _ => unreachable!(),
        };
        let node = *state
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .ok_or(CompatErrno::NoEntry)?;
        let (translated, translated_cookie, translated_type) =
            if recipient == node.owner {
                (
                    node.pointer,
                    node.cookie,
                    if weak {
                        BINDER_TYPE_WEAK_BINDER
                    } else {
                        BINDER_TYPE_BINDER
                    },
                )
            } else {
                let handle = if let Some(binding) = state.handles.iter().find(|binding| {
                    binding.recipient == recipient && binding.node == node_id
                }) {
                    binding.handle
                } else {
                    if state.handles.len() >= MAX_HANDLES {
                        return Err(CompatErrno::NoSpace);
                    }
                    let handle = state.next_handle;
                    state.next_handle = handle.checked_add(1).ok_or(CompatErrno::NoSpace)?;
                    state.handles.push(LocalHandle {
                        recipient,
                        node: node_id,
                        handle,
                    });
                    handle
                };
                (
                    u64::from(handle),
                    0,
                    if weak {
                        BINDER_TYPE_WEAK_HANDLE
                    } else {
                        BINDER_TYPE_HANDLE
                    },
                )
            };
        let object = &mut data[offset..offset + FLAT_BINDER_OBJECT_BYTES];
        object[..4].copy_from_slice(&translated_type.to_le_bytes());
        object[8..16].copy_from_slice(&translated.to_le_bytes());
        object[16..24].copy_from_slice(&translated_cookie.to_le_bytes());
        }
        Ok(())
    })();
    if result.is_err() {
        for installed in installed_fds {
            let _ = proc::linux_close_fd(recipient, installed);
        }
    }
    result
}

fn enqueue_transaction(
    pid: ObjId,
    command: u32,
    transaction: &[u8],
) -> Result<(), CompatErrno> {
    let flags = u32::from_le_bytes(transaction[20..24].try_into().unwrap());
    if flags & !TF_ONE_WAY != 0 {
        return Err(CompatErrno::Invalid);
    }
    let code = u32::from_le_bytes(transaction[16..20].try_into().unwrap());
    let data_size = usize::try_from(u64::from_le_bytes(transaction[32..40].try_into().unwrap()))
        .map_err(|_| CompatErrno::Invalid)?;
    let offsets_size =
        usize::try_from(u64::from_le_bytes(transaction[40..48].try_into().unwrap()))
            .map_err(|_| CompatErrno::Invalid)?;
    if data_size > MAX_TRANSACTION_BYTES || offsets_size > MAX_OFFSET_BYTES {
        return Err(CompatErrno::Invalid);
    }
    let data_pointer = u64::from_le_bytes(transaction[48..56].try_into().unwrap());
    let offsets_pointer = u64::from_le_bytes(transaction[56..64].try_into().unwrap());
    let mut data = alloc::vec![0u8; data_size];
    let mut offsets = alloc::vec![0u8; offsets_size];
    if data_size != 0 {
        copy_from_user(&mut data, data_pointer, data_size).map_err(|_| CompatErrno::Fault)?;
    }
    if offsets_size != 0 {
        copy_from_user(&mut offsets, offsets_pointer, offsets_size)
            .map_err(|_| CompatErrno::Fault)?;
    }

    if command == BC_TRANSACTION {
        let handle = u32::from_le_bytes(transaction[0..4].try_into().unwrap());
        let target = match resolve_transaction_target(pid, handle) {
            Ok(target) => target,
            Err(CompatErrno::NoEntry | CompatErrno::BadFd) => {
                queue_reply_error(pid, BR_FAILED_REPLY, CompatErrno::Invalid)?;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if target == pid {
            return Err(CompatErrno::Invalid);
        }
        if proc::state(target) != Some(proc::ProcState::Running) {
            queue_reply_error(pid, BR_DEAD_REPLY, CompatErrno::NoProcess)?;
            return Ok(());
        }
        let one_way = flags & TF_ONE_WAY != 0;
        let frozen = process_is_frozen(target);
        if frozen && !one_way {
            note_frozen_transaction(target, false);
            queue_reply_error(pid, BR_FROZEN_REPLY, CompatErrno::Busy)?;
            return Ok(());
        }
        if let Err(error) = translate_objects(pid, target, &mut data, &offsets) {
            if matches!(error, CompatErrno::Invalid | CompatErrno::NoEntry | CompatErrno::BadFd) {
                queue_reply_error(pid, BR_FAILED_REPLY, CompatErrno::Invalid)?;
                return Ok(());
            }
            return Err(error);
        }
        let max_threads = proc::linux_binder_max_threads(target).unwrap_or(0) as usize;
        let mut state = BINDER.lock();
        let active_pool_threads = state
            .threads
            .iter()
            .filter(|thread| thread.process == target && thread.pool_member)
            .count();
        let request_spawn = max_threads != 0
            && active_pool_threads < max_threads
            && !state.spawn_pending.contains(&target)
            && !frozen;
        crate::kprintln!(
            "[JSR-BINDER] transaction sender={} target={} code={:#x} flags={:#x} max_threads={} active_pool={} spawn={}",
            pid.raw(),
            target.raw(),
            code,
            flags,
            max_threads,
            active_pool_threads,
            request_spawn
        );
        let spam_suspect = one_way && note_oneway_spam(&mut state, pid, target);
        let queued = 2
            + usize::from(request_spawn)
            + usize::from(frozen && one_way)
            + usize::from(spam_suspect);
        if state.queue.len().saturating_add(queued) > MAX_QUEUE {
            return Err(CompatErrno::TryAgain);
        }
        state
            .queue
            .try_reserve(queued)
            .map_err(|_| CompatErrno::NoMemory)?;
        if flags & TF_ONE_WAY == 0 {
            state.active.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
        }
        if request_spawn {
            state
                .spawn_pending
                .try_reserve(1)
                .map_err(|_| CompatErrno::NoMemory)?;
            state.spawn_pending.push(target);
            state
                .queue
                .push_back((target, QueuedCommand::SpawnLooper));
        }
        state.queue.push_back((pid, QueuedCommand::Complete));
        if frozen && one_way {
            state.queue.push_back((
                pid,
                QueuedCommand::ReplyError {
                    command: BR_TRANSACTION_PENDING_FROZEN,
                },
            ));
        }
        if spam_suspect {
            state.queue.push_back((
                pid,
                QueuedCommand::ReplyError {
                    command: BR_ONEWAY_SPAM_SUSPECT,
                },
            ));
        }
        state.queue.push_back((
            target,
            QueuedCommand::Transaction {
                command: BR_TRANSACTION,
                sender: pid,
                code,
                flags,
                data,
                offsets,
            },
        ));
        if !one_way {
            state.active.push(ActiveTransaction {
                target,
                sender: pid,
            });
        }
        let mut wake = [None; MAX_BINDER_THREADS];
        for (slot, thread) in wake.iter_mut().zip(
            state
                .threads
                .iter()
                .filter(|thread| thread.process == target),
        ) {
            *slot = Some(thread.task);
        }
        drop(state);
        if frozen && one_way {
            note_frozen_transaction(target, true);
        }
        for task in wake.into_iter().flatten() {
            crate::sched::wake(task);
        }
        return Ok(());
    }

    let sender = {
        let state = BINDER.lock();
        state
            .active
            .iter()
            .rfind(|active| active.target == pid)
            .map(|active| active.sender)
    };
    let Some(sender) = sender else {
        queue_reply_error(pid, BR_FAILED_REPLY, CompatErrno::Invalid)?;
        return Ok(());
    };
    if proc::state(sender) != Some(proc::ProcState::Running) {
        queue_reply_error(pid, BR_DEAD_REPLY, CompatErrno::NoProcess)?;
        return Ok(());
    }
    translate_objects(pid, sender, &mut data, &offsets)?;
    let mut state = BINDER.lock();
    let index = state
        .active
        .iter()
        .rposition(|active| active.target == pid)
        .ok_or(CompatErrno::Invalid)?;
    state.active.remove(index);
    if state.queue.len().saturating_add(2) > MAX_QUEUE {
        state.active.push(ActiveTransaction {
            target: pid,
            sender,
        });
        return Err(CompatErrno::TryAgain);
    }
    if state.queue.try_reserve(2).is_err() {
        state.active.push(ActiveTransaction {
            target: pid,
            sender,
        });
        return Err(CompatErrno::NoMemory);
    }
    state.queue.push_back((pid, QueuedCommand::Complete));
    state.queue.push_back((
        sender,
        QueuedCommand::Transaction {
            command: BR_REPLY,
            sender: pid,
            code,
            flags: 0,
            data,
            offsets,
        },
    ));
    Ok(())
}

fn deliver(
    recipient: ObjId,
    address: u64,
    capacity: usize,
    command: QueuedCommand,
) -> Result<usize, CompatErrno> {
    match command {
        QueuedCommand::Complete => {
            if capacity < 4 {
                return Err(CompatErrno::Range);
            }
            copy_to_user(
                address,
                &BR_TRANSACTION_COMPLETE.to_le_bytes(),
                4,
            )
            .map_err(|_| CompatErrno::Fault)?;
            Ok(4)
        }
        QueuedCommand::ReplyError { command } => {
            if capacity < 4 {
                return Err(CompatErrno::Range);
            }
            crate::kprintln!(
                "[JSR-BINDER] reply-error-deliver recipient={} command={:#x}",
                recipient.raw(),
                command
            );
            copy_to_user(address, &command.to_le_bytes(), 4).map_err(|_| CompatErrno::Fault)?;
            Ok(4)
        }
        QueuedCommand::SpawnLooper => {
            if capacity < 4 {
                return Err(CompatErrno::Range);
            }
            crate::kprintln!(
                "[JSR-BINDER] spawn-deliver recipient={}",
                recipient.raw()
            );
            copy_to_user(
                address,
                &BR_SPAWN_LOOPER.to_le_bytes(),
                4,
            )
            .map_err(|_| CompatErrno::Fault)?;
            Ok(4)
        }
        QueuedCommand::DeathNotification { command, cookie } => {
            if capacity < 12 {
                return Err(CompatErrno::Range);
            }
            let mut packet = [0u8; 12];
            packet[..4].copy_from_slice(&command.to_le_bytes());
            packet[4..12].copy_from_slice(&cookie.to_le_bytes());
            copy_to_user(address, &packet, packet.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(packet.len())
        }
        QueuedCommand::Transaction {
            command,
            sender,
            code,
            flags,
            data,
            offsets,
        } => {
            if capacity < BINDER_READ_PACKET_BYTES {
                return Err(CompatErrno::Range);
            }
            crate::kprintln!(
                "[JSR-BINDER] transaction-deliver recipient={} sender={} command={:#x} code={:#x} flags={:#x}",
                recipient.raw(),
                sender.raw(),
                command,
                code,
                flags
            );
            let combined_length = data
                .len()
                .checked_add(offsets.len())
                .ok_or(CompatErrno::Invalid)?;
            let mut combined = Vec::new();
            combined
                .try_reserve(combined_length)
                .map_err(|_| CompatErrno::NoMemory)?;
            combined.extend_from_slice(&data);
            combined.extend_from_slice(&offsets);
            let buffer = proc::linux_alloc_transaction_buffer(recipient, &combined)
                .ok_or(CompatErrno::NoMemory)?;
            {
                let mut state = BINDER.lock();
                if state.buffers.try_reserve(1).is_err() {
                    drop(state);
                    let _ = proc::linux_free_transaction_buffer(
                        recipient,
                        buffer,
                        combined_length,
                    );
                    return Err(CompatErrno::NoMemory);
                }
                state.buffers.push(TransactionBuffer {
                    process: recipient,
                    address: buffer,
                    length: combined_length,
                });
            }
            let mut packet = [0u8; BINDER_READ_PACKET_BYTES];
            packet[0..4].copy_from_slice(&command.to_le_bytes());
            let transaction = &mut packet[4..];
            transaction[0..8].copy_from_slice(&0u64.to_le_bytes());
            transaction[8..16].copy_from_slice(&0u64.to_le_bytes());
            transaction[16..20].copy_from_slice(&code.to_le_bytes());
            transaction[20..24].copy_from_slice(&flags.to_le_bytes());
            let sender_pid = proc::linux_pid(sender).unwrap_or(0);
            transaction[24..28].copy_from_slice(&(sender_pid as i32).to_le_bytes());
            transaction[28..32].copy_from_slice(&0u32.to_le_bytes());
            transaction[32..40].copy_from_slice(&(data.len() as u64).to_le_bytes());
            transaction[40..48].copy_from_slice(&(offsets.len() as u64).to_le_bytes());
            transaction[48..56].copy_from_slice(&buffer.to_le_bytes());
            transaction[56..64]
                .copy_from_slice(&(buffer + data.len() as u64).to_le_bytes());
            copy_to_user(address, &packet, packet.len()).map_err(|_| CompatErrno::Fault)?;
            Ok(packet.len())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oneway_spam_threshold_is_per_sender_and_target() {
        let sender = ObjId::from_raw(1).unwrap();
        let target = ObjId::from_raw(2).unwrap();
        let other = ObjId::from_raw(3).unwrap();
        let mut state = State::new();
        state.oneway_spam.push(sender);
        for _ in 1..ONEWAY_SPAM_SUSPECT_THRESHOLD {
            assert!(!note_oneway_spam(&mut state, sender, target));
        }
        assert!(note_oneway_spam(&mut state, sender, target));
        assert!(!note_oneway_spam(&mut state, sender, other));
        assert!(!note_oneway_spam(&mut state, other, target));
    }
}
