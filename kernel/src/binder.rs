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
const BR_TRANSACTION_COMPLETE: u32 = 0x7206;
const BR_DEAD_BINDER: u32 = 0x8008_720f;
const BR_CLEAR_DEATH_NOTIFICATION_DONE: u32 = 0x8008_7210;
const TF_ONE_WAY: u32 = 0x01;

enum QueuedCommand {
    Complete,
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
struct Node {
    id: u64,
    owner: ObjId,
    pointer: u64,
    cookie: u64,
    strong_refs: u32,
    weak_refs: u32,
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
    for node in state.nodes.iter().filter(|node| node.owner == pid) {
        dead_nodes[dead_count] = node.id;
        dead_count += 1;
    }
    let notifications = state
        .death_requests
        .iter()
        .filter(|request| dead_nodes[..dead_count].contains(&request.node))
        .count();
    if state.queue.try_reserve(notifications).is_ok() {
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
    }
    state.nodes.retain(|node| node.owner != pid);
    state.handles.retain(|binding| binding.recipient != pid);
    state
        .death_requests
        .retain(|request| request.recipient != pid);
    state.active.retain(|active| active.target != pid && active.sender != pid);
    state.buffers.retain(|buffer| buffer.process != pid);
    state.queue.retain(|(target, command)| {
        *target != pid
            && !matches!(command, QueuedCommand::Transaction { sender, .. } if *sender == pid)
    });
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
    let read_consumed = loop {
        let queued = {
            let mut state = BINDER.lock();
            state
                .queue
                .iter()
                .position(|(target, _)| *target == pid)
                .and_then(|index| state.queue.remove(index))
                .map(|(_, command)| command)
        };
        if let Some(command) = queued {
            break deliver(pid, read_buffer, read_size, command)?;
        }
        if read_size < 4 || nonblocking {
            break 0;
        }
        if proc::current_exiting() || crate::linux_abi::current_signal_pending(pid) {
            return Err(CompatErrno::Interrupted);
        }
        crate::sched::pause();
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
                offset += 4;
            }
            _ => return Err(CompatErrno::NoSys),
        }
    }
    Ok(offset)
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
        let target = resolve_transaction_target(pid, handle)?;
        if target == pid {
            return Err(CompatErrno::Invalid);
        }
        translate_objects(pid, target, &mut data, &offsets)?;
        let mut state = BINDER.lock();
        if state.queue.len() >= MAX_QUEUE {
            return Err(CompatErrno::TryAgain);
        }
        state.queue.try_reserve(2).map_err(|_| CompatErrno::NoMemory)?;
        if flags & TF_ONE_WAY == 0 {
            state.active.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
        }
        state.queue.push_back((pid, QueuedCommand::Complete));
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
        if flags & TF_ONE_WAY == 0 {
            state.active.push(ActiveTransaction {
                target,
                sender: pid,
            });
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
            .ok_or(CompatErrno::Invalid)?
    };
    translate_objects(pid, sender, &mut data, &offsets)?;
    let mut state = BINDER.lock();
    let index = state
        .active
        .iter()
        .rposition(|active| active.target == pid)
        .ok_or(CompatErrno::Invalid)?;
    state.active.remove(index);
    state.queue.try_reserve(2).map_err(|_| CompatErrno::NoMemory)?;
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
