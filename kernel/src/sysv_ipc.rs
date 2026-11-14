//! Bounded System V message-queue compatibility service.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use compat_core::syscall::CompatErrno;
use kernel_core::objtable::ObjId;

use crate::mm::user::{copy_from_user, copy_to_user};
use crate::sync::IrqSpinLock;

const MAX_QUEUES: usize = 64;
const MAX_QUEUE_MESSAGES: usize = 64;
const MAX_MESSAGE_BYTES: usize = 8192;
const MAX_QUEUE_BYTES: usize = 16384;
const MAX_TOTAL_MESSAGES: usize = MAX_QUEUES * MAX_QUEUE_MESSAGES;
const MAX_TOTAL_BYTES: usize = MAX_QUEUES * MAX_QUEUE_BYTES;
const MAX_WAITERS: usize = 64;

const IPC_CREAT: u32 = 0o1000;
const IPC_EXCL: u32 = 0o2000;
const IPC_NOWAIT: u32 = 0o4000;
const IPC_RMID: u32 = 0;
const IPC_SET: u32 = 1;
const IPC_STAT: u32 = 2;
const IPC_INFO: u32 = 3;
const MSG_STAT: u32 = 11;
const MSG_INFO: u32 = 12;
const MSG_STAT_ANY: u32 = 13;
const MSG_NOERROR: u32 = 0o10000;
const MSG_EXCEPT: u32 = 0o20000;
const MSG_COPY: u32 = 0o40000;

const MSQID_DS_BYTES: usize = 120;
const MSGINFO_BYTES: usize = 32;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

#[derive(Clone)]
pub(crate) struct Caller {
    pub(crate) process: ObjId,
    pub(crate) pid: u32,
    pub(crate) euid: u32,
    pub(crate) egid: u32,
    pub(crate) groups: Vec<u32>,
    pub(crate) cap_effective: u64,
    pub(crate) now: u64,
}

impl Caller {
    fn privileged(&self) -> bool {
        self.cap_effective & CAP_SYS_RESOURCE != 0
    }
}

struct Message {
    mtype: i64,
    text: Vec<u8>,
}

struct Queue {
    id: u32,
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    qbytes: usize,
    bytes: usize,
    stime: u64,
    rtime: u64,
    ctime: u64,
    lspid: u32,
    lrpid: u32,
    messages: VecDeque<Message>,
    send_waiters: Vec<crate::task::TaskId>,
    recv_waiters: Vec<crate::task::TaskId>,
}

struct State {
    queues: Vec<Queue>,
    next_id: u32,
    total_messages: usize,
    total_bytes: usize,
}

impl State {
    const fn new() -> Self {
        Self {
            queues: Vec::new(),
            next_id: 1,
            total_messages: 0,
            total_bytes: 0,
        }
    }
}

static QUEUES: IrqSpinLock<State> =
    IrqSpinLock::ranked(crate::lockorder::SYSV_IPC, State::new());

fn flags32(raw: u64) -> Result<u32, CompatErrno> {
    let flags = raw as u32;
    if u64::from(flags) == raw {
        Ok(flags)
    } else {
        Err(CompatErrno::Invalid)
    }
}

fn permissions_allow(queue: &Queue, caller: &Caller, requested: u32) -> bool {
    if caller.privileged() {
        return true;
    }
    let bits = if caller.euid == queue.uid || caller.euid == queue.cuid {
        (queue.mode >> 6) & 7
    } else if caller.egid == queue.gid
        || caller.egid == queue.cgid
        || caller.groups.contains(&queue.gid)
        || caller.groups.contains(&queue.cgid)
    {
        (queue.mode >> 3) & 7
    } else {
        queue.mode & 7
    };
    bits & requested == requested
}

pub(crate) fn msgget(caller: &Caller, key: i32, raw_flags: u64) -> Result<u64, CompatErrno> {
    let flags = flags32(raw_flags)?;
    if flags & !(0o777 | IPC_CREAT | IPC_EXCL) != 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut state = QUEUES.lock();
    if key != 0 {
        if let Some(queue) = state.queues.iter().find(|queue| queue.key == key) {
            if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                return Err(CompatErrno::Exists);
            }
            return Ok(u64::from(queue.id));
        }
        if flags & IPC_CREAT == 0 {
            return Err(CompatErrno::NoEntry);
        }
    }
    if state.queues.len() >= MAX_QUEUES {
        return Err(CompatErrno::NoSpace);
    }
    state
        .queues
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    let mut id = state.next_id;
    while id == 0 || state.queues.iter().any(|queue| queue.id == id) {
        id = id.wrapping_add(1);
        if id == 0 {
            id = 1;
        }
    }
    state.next_id = id.wrapping_add(1).max(1);
    state.queues.push(Queue {
        id,
        key,
        uid: caller.euid,
        gid: caller.egid,
        cuid: caller.euid,
        cgid: caller.egid,
        mode: flags & 0o777,
        qbytes: MAX_QUEUE_BYTES,
        bytes: 0,
        stime: 0,
        rtime: 0,
        ctime: caller.now,
        lspid: 0,
        lrpid: 0,
        messages: VecDeque::new(),
        send_waiters: Vec::new(),
        recv_waiters: Vec::new(),
    });
    Ok(u64::from(id))
}

fn msginfo_bytes(queues: usize) -> [u8; MSGINFO_BYTES] {
    let mut output = [0u8; MSGINFO_BYTES];
    output[0..4].copy_from_slice(&0i32.to_le_bytes());
    output[4..8].copy_from_slice(&(MAX_TOTAL_MESSAGES as i32).to_le_bytes());
    output[8..12].copy_from_slice(&(MAX_MESSAGE_BYTES as i32).to_le_bytes());
    output[12..16].copy_from_slice(&(MAX_QUEUE_BYTES as i32).to_le_bytes());
    output[16..20].copy_from_slice(&(MAX_QUEUES as i32).to_le_bytes());
    output[20..24].copy_from_slice(&16i32.to_le_bytes());
    output[24..28].copy_from_slice(&(MAX_TOTAL_MESSAGES as i32).to_le_bytes());
    output[28..30].copy_from_slice(&(queues.min(u16::MAX as usize) as u16).to_le_bytes());
    output
}

fn queue_info_bytes(queue: &Queue) -> [u8; MSQID_DS_BYTES] {
    let mut output = [0u8; MSQID_DS_BYTES];
    output[0..4].copy_from_slice(&queue.key.to_le_bytes());
    output[4..8].copy_from_slice(&queue.uid.to_le_bytes());
    output[8..12].copy_from_slice(&queue.gid.to_le_bytes());
    output[12..16].copy_from_slice(&queue.cuid.to_le_bytes());
    output[16..20].copy_from_slice(&queue.cgid.to_le_bytes());
    output[20..24].copy_from_slice(&queue.mode.to_le_bytes());
    output[24..26].copy_from_slice(&(queue.id as u16).to_le_bytes());
    output[48..56].copy_from_slice(&queue.stime.to_le_bytes());
    output[56..64].copy_from_slice(&queue.rtime.to_le_bytes());
    output[64..72].copy_from_slice(&queue.ctime.to_le_bytes());
    output[72..80].copy_from_slice(&(queue.bytes as u64).to_le_bytes());
    output[80..88].copy_from_slice(&(queue.messages.len() as u64).to_le_bytes());
    output[88..96].copy_from_slice(&(queue.qbytes as u64).to_le_bytes());
    output[96..100].copy_from_slice(&queue.lspid.to_le_bytes());
    output[100..104].copy_from_slice(&queue.lrpid.to_le_bytes());
    output
}

pub(crate) fn msgctl(
    caller: &Caller,
    id: i32,
    raw_command: u64,
    address: u64,
) -> Result<u64, CompatErrno> {
    let command = flags32(raw_command)?;
    let set_fields = if command == IPC_SET {
        if address == 0 {
            return Err(CompatErrno::Fault);
        }
        let mut input = [0u8; MSQID_DS_BYTES];
        copy_from_user(&mut input, address, MSQID_DS_BYTES).map_err(|_| CompatErrno::Fault)?;
        let uid = u32::from_le_bytes(input[4..8].try_into().unwrap());
        let gid = u32::from_le_bytes(input[8..12].try_into().unwrap());
        let mode = u32::from_le_bytes(input[20..24].try_into().unwrap());
        let qbytes = u64::from_le_bytes(input[88..96].try_into().unwrap());
        if mode & !0o777 != 0 || qbytes == 0 || qbytes > MAX_QUEUE_BYTES as u64 {
            return Err(CompatErrno::Invalid);
        }
        Some((uid, gid, mode, qbytes as usize))
    } else {
        None
    };
    if command == IPC_INFO {
        if address == 0 {
            return Err(CompatErrno::Fault);
        }
        let state = QUEUES.lock();
        let output = msginfo_bytes(state.queues.len());
        drop(state);
        copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
        return Ok(0);
    }
    if command == MSG_INFO {
        if address == 0 {
            return Err(CompatErrno::Fault);
        }
        let state = QUEUES.lock();
        let output = msginfo_bytes(state.queues.len());
        drop(state);
        copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
        return Ok(0);
    }
    let mut state = QUEUES.lock();
    let index = state
        .queues
        .iter()
        .position(|queue| queue.id == id as u32 && id >= 0)
        .ok_or(CompatErrno::Invalid)?;
    match command {
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            if address == 0 {
                return Err(CompatErrno::Fault);
            }
            if command != MSG_STAT_ANY
                && !permissions_allow(&state.queues[index], caller, 4)
            {
                return Err(CompatErrno::Access);
            }
            let output = queue_info_bytes(&state.queues[index]);
            let id = state.queues[index].id;
            drop(state);
            copy_to_user(address, &output, output.len()).map_err(|_| CompatErrno::Fault)?;
            if command == IPC_STAT {
                Ok(0)
            } else {
                Ok(u64::from(id))
            }
        }
        IPC_SET => {
            if caller.euid != state.queues[index].uid && !caller.privileged() {
                return Err(CompatErrno::Perm);
            }
            let (uid, gid, mode, qbytes) = set_fields.expect("IPC_SET fields preflighted");
            let queue = &mut state.queues[index];
            queue.uid = uid;
            queue.gid = gid;
            queue.mode = mode;
            queue.qbytes = qbytes;
            queue.ctime = caller.now;
            Ok(0)
        }
        IPC_RMID => {
            if caller.euid != state.queues[index].uid && !caller.privileged() {
                return Err(CompatErrno::Perm);
            }
            let queue = state.queues.remove(index);
            state.total_messages = state.total_messages.saturating_sub(queue.messages.len());
            state.total_bytes = state.total_bytes.saturating_sub(queue.bytes);
            let mut wake = queue.send_waiters;
            wake.extend(queue.recv_waiters);
            drop(state);
            for task in wake {
                crate::sched::wake(task);
            }
            Ok(0)
        }
        _ => Err(CompatErrno::Invalid),
    }
}

fn wait_blocked(caller: &Caller) -> Result<(), CompatErrno> {
    if crate::proc::current_exiting() || crate::linux_abi::current_signal_pending(caller.process) {
        return Err(CompatErrno::Interrupted);
    }
    crate::sched::pause();
    Ok(())
}

fn add_waiter(
    waiters: &mut Vec<crate::task::TaskId>,
    task: crate::task::TaskId,
) -> Result<(), CompatErrno> {
    if waiters.contains(&task) {
        return Ok(());
    }
    if waiters.len() >= MAX_WAITERS {
        return Err(CompatErrno::NoSpace);
    }
    waiters
        .try_reserve(1)
        .map_err(|_| CompatErrno::NoMemory)?;
    waiters.push(task);
    Ok(())
}

fn remove_waiter(waiters: &mut Vec<crate::task::TaskId>, task: crate::task::TaskId) {
    if let Some(index) = waiters.iter().position(|waiter| *waiter == task) {
        waiters.swap_remove(index);
    }
}

pub(crate) fn msgsnd(
    caller: &Caller,
    id: i32,
    message_address: u64,
    message_size: u64,
    raw_flags: u64,
) -> Result<u64, CompatErrno> {
    let flags = flags32(raw_flags)?;
    if flags & !IPC_NOWAIT != 0 {
        return Err(CompatErrno::Invalid);
    }
    let message_size = usize::try_from(message_size).map_err(|_| CompatErrno::TooBig)?;
    if message_size > MAX_MESSAGE_BYTES {
        return Err(CompatErrno::TooBig);
    }
    if message_address == 0 {
        return Err(CompatErrno::Fault);
    }
    let mut raw_type = [0u8; 8];
    copy_from_user(&mut raw_type, message_address, 8).map_err(|_| CompatErrno::Fault)?;
    let mtype = i64::from_le_bytes(raw_type);
    if mtype <= 0 {
        return Err(CompatErrno::Invalid);
    }
    let mut text = Vec::new();
    text.try_reserve(message_size)
        .map_err(|_| CompatErrno::NoMemory)?;
    text.resize(message_size, 0);
    if message_size != 0 {
        let text_address = message_address
            .checked_add(8)
            .ok_or(CompatErrno::Fault)?;
        copy_from_user(
            &mut text,
            text_address,
            message_size,
        )
        .map_err(|_| CompatErrno::Fault)?;
    }
    let mut message = Some(Message { mtype, text });
    let task = crate::sched::current().0;
    let mut waited = false;
    loop {
        let mut state = QUEUES.lock();
        let queue_index = match state
            .queues
            .iter()
            .position(|queue| queue.id == id as u32 && id >= 0)
        {
            Some(index) => index,
            None if waited => return Err(CompatErrno::NoId),
            None => return Err(CompatErrno::Invalid),
        };
        let global_has_room = state.total_messages < MAX_TOTAL_MESSAGES
            && state.total_bytes + message.as_ref().map_or(0, |message| message.text.len())
                <= MAX_TOTAL_BYTES;
        let queue = &mut state.queues[queue_index];
        if !permissions_allow(queue, caller, 2) {
            return Err(CompatErrno::Access);
        }
        let bytes = message.as_ref().map_or(0, |message| message.text.len());
        if bytes > queue.qbytes {
            return Err(CompatErrno::TooBig);
        }
        let queue_has_room =
            queue.messages.len() < MAX_QUEUE_MESSAGES && queue.bytes + bytes <= queue.qbytes;
        if queue_has_room && global_has_room {
            remove_waiter(&mut queue.send_waiters, task);
            queue.messages.try_reserve(1).map_err(|_| CompatErrno::NoMemory)?;
            queue.messages.push_back(message.take().expect("message queued once"));
            queue.bytes += bytes;
            queue.stime = caller.now;
            queue.lspid = caller.pid;
            let wake = core::mem::take(&mut queue.recv_waiters);
            state.total_messages += 1;
            state.total_bytes += bytes;
            drop(state);
            for task in wake {
                crate::sched::wake(task);
            }
            return Ok(message_size as u64);
        }
        if flags & IPC_NOWAIT != 0 {
            return Err(CompatErrno::TryAgain);
        }
        add_waiter(&mut queue.send_waiters, task)?;
        drop(state);
        waited = true;
        wait_blocked(caller)?;
        let mut state = QUEUES.lock();
        if let Some(queue) = state.queues.iter_mut().find(|queue| queue.id == id as u32) {
            remove_waiter(&mut queue.send_waiters, task);
        }
    }
}

fn selected_message(queue: &Queue, msgtyp: i64, except: bool, copy: bool) -> Option<usize> {
    if copy {
        let index = usize::try_from(msgtyp).ok()?;
        return (index < queue.messages.len()).then_some(index);
    }
    if msgtyp == 0 {
        return (!queue.messages.is_empty()).then_some(0);
    }
    if msgtyp > 0 {
        return queue
            .messages
            .iter()
            .position(|message| (message.mtype == msgtyp) != except);
    }
    if except {
        return None;
    }
    let limit = msgtyp.checked_neg()?;
    let mut selected = None;
    let mut selected_type = i64::MAX;
    for (index, message) in queue.messages.iter().enumerate() {
        if message.mtype <= limit && message.mtype < selected_type {
            selected = Some(index);
            selected_type = message.mtype;
        }
    }
    selected
}

fn restore_received(id: i32, index: usize, message: Message) {
    let mut state = QUEUES.lock();
    let Some(queue_index) = state.queues.iter().position(|queue| queue.id == id as u32) else {
        return;
    };
    let bytes = message.text.len();
    let wake = {
        let queue = &mut state.queues[queue_index];
        let position = index.min(queue.messages.len());
        queue.messages.insert(position, message);
        queue.bytes += bytes;
        core::mem::take(&mut queue.recv_waiters)
    };
    state.total_messages += 1;
    state.total_bytes += bytes;
    drop(state);
    for task in wake {
        crate::sched::wake(task);
    }
}

pub(crate) fn msgrcv(
    caller: &Caller,
    id: i32,
    message_address: u64,
    message_size: u64,
    msgtyp: i64,
    raw_flags: u64,
) -> Result<u64, CompatErrno> {
    let flags = flags32(raw_flags)?;
    if flags & !(IPC_NOWAIT | MSG_NOERROR | MSG_EXCEPT | MSG_COPY) != 0
        || flags & MSG_COPY != 0 && flags & MSG_EXCEPT != 0
        || flags & MSG_EXCEPT != 0 && msgtyp <= 0
    {
        return Err(CompatErrno::Invalid);
    }
    let message_size = usize::try_from(message_size).map_err(|_| CompatErrno::Invalid)?;
    if message_address == 0 {
        return Err(CompatErrno::Fault);
    }
    let task = crate::sched::current().0;
    let copy = flags & MSG_COPY != 0;
    let noerror = flags & MSG_NOERROR != 0;
    let except = flags & MSG_EXCEPT != 0;
    let mut waited = false;
    loop {
        let mut state = QUEUES.lock();
        let queue_index = match state.queues.iter().position(|queue| queue.id == id as u32 && id >= 0)
        {
            Some(index) => index,
            None if waited => return Err(CompatErrno::NoId),
            None => return Err(CompatErrno::Invalid),
        };
        let queue = &state.queues[queue_index];
        if !permissions_allow(queue, caller, 4) {
            return Err(CompatErrno::Access);
        }
        let Some(index) = selected_message(queue, msgtyp, except, copy) else {
            if flags & IPC_NOWAIT != 0 || copy {
                return Err(CompatErrno::NoMessage);
            }
            let queue = &mut state.queues[queue_index];
            add_waiter(&mut queue.recv_waiters, task)?;
            drop(state);
            waited = true;
            wait_blocked(caller)?;
            let mut state = QUEUES.lock();
            if let Some(queue) = state.queues.iter_mut().find(|queue| queue.id == id as u32) {
                remove_waiter(&mut queue.recv_waiters, task);
            }
            continue;
        };
        let selected_length = queue.messages[index].text.len();
        if selected_length > message_size && !noerror {
            return Err(CompatErrno::TooBig);
        }
        drop(state);
        let pin_bytes = 8 + selected_length.min(message_size).min(MAX_MESSAGE_BYTES);
        let pinned = crate::kobj::with(|table| {
            crate::proc::pin_user_in(table, caller.process, message_address, pin_bytes, true)
        })
        .map_err(|error| match error {
            crate::proc::ProcError::OutOfFrames | crate::proc::ProcError::MemoryQuota => {
                CompatErrno::NoMemory
            }
            _ => CompatErrno::Fault,
        })?;
        let mut state = QUEUES.lock();
        let queue_index = match state
            .queues
            .iter()
            .position(|queue| queue.id == id as u32 && id >= 0)
        {
            Some(index) => index,
            None => return Err(CompatErrno::NoId),
        };
        let queue = &mut state.queues[queue_index];
        if !permissions_allow(queue, caller, 4) {
            return Err(CompatErrno::Access);
        }
        let Some(index) = selected_message(queue, msgtyp, except, copy) else {
            if flags & IPC_NOWAIT != 0 || copy {
                return Err(CompatErrno::NoMessage);
            }
            add_waiter(&mut queue.recv_waiters, task)?;
            drop(state);
            wait_blocked(caller)?;
            continue;
        };
        let selected_length = queue.messages[index].text.len();
        if selected_length > message_size && !noerror {
            return Err(CompatErrno::TooBig);
        }
        let take = selected_length.min(message_size);
        let (message, wake) = if copy {
            let source = &queue.messages[index];
            let mut text = Vec::new();
            text.try_reserve(source.text.len())
                .map_err(|_| CompatErrno::NoMemory)?;
            text.extend_from_slice(&source.text);
            (Message { mtype: source.mtype, text }, Vec::new())
        } else {
            let (message, removed_len, wake) = {
                remove_waiter(&mut queue.recv_waiters, task);
                let message = queue.messages.remove(index).expect("selected message exists");
                let removed_len = message.text.len();
                queue.bytes = queue.bytes.saturating_sub(removed_len);
                queue.rtime = caller.now;
                queue.lrpid = caller.pid;
                (
                    message,
                    removed_len,
                    core::mem::take(&mut queue.send_waiters),
                )
            };
            state.total_messages = state.total_messages.saturating_sub(1);
            state.total_bytes = state.total_bytes.saturating_sub(removed_len);
            (message, wake)
        };
        drop(state);
        for task in wake {
            crate::sched::wake(task);
        }
        let type_written = pinned.write_at(0, &message.mtype.to_le_bytes());
        let text_written = take == 0 || pinned.write_at(8, &message.text[..take]);
        if !type_written || !text_written {
            if !copy {
                restore_received(id, index, message);
            }
            return Err(CompatErrno::Fault);
        }
        return Ok(take as u64);
    }
}
