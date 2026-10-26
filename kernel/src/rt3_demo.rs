//! RT-3 isolated acceptance: real CPL3 mutex calls and classic inversion.
//! Timing is not a physical performance claim; the hard checks are donation,
//! direct hand-off, termination and object/frame reclamation.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use kernel_core::frame::FRAME_SIZE;
use kernel_core::paging::MapFlags;
use kernel_core::sched::Qos;

use crate::kobj;
use crate::proc::{self, ProcState};
use crate::sched;
use crate::syscall::{table as abi, SyscallSet};
use crate::task::TaskId;
use crate::{arch, kprintln};

static FAILED: AtomicU32 = AtomicU32::new(0);
static DONATED: AtomicU32 = AtomicU32::new(0);
static IPC_DONATED: AtomicU32 = AtomicU32::new(0);
static LOW_TASK: AtomicU64 = AtomicU64::new(0);
static USER_RING: &[u8] = include_bytes!(env!("JSR_USER_RING"));
const STACK_TOP_OFF: u64 = 0xC0_0000;
const STACK_PAGES: u64 = 4;

fn check(ok: bool, what: &str) {
    if !ok { FAILED.fetch_add(1,Ordering::Relaxed);kprintln!("[JSR-RT3-FAIL] {}",what); }
}

pub(crate) fn observe_unlock(task:TaskId,base:Option<Qos>,effective:Option<Qos>) {
    if task.0==LOW_TASK.load(Ordering::Relaxed) && base==Some(Qos::Background) && effective==Some(Qos::UserInitiated) {
        DONATED.store(1,Ordering::Relaxed);
    }
}

pub(crate) fn observe_ipc_service(base:Option<Qos>,effective:Option<Qos>) {
    if base==Some(Qos::Background) && effective==Some(Qos::UserInitiated) {
        IPC_DONATED.store(1,Ordering::Relaxed);
    }
}

pub fn run()->u32 {
    let baseline=(kobj::stats(),crate::mm::frame::free_frames());
    let calls=SyscallSet::of(&[
        abi::SYSTEM_TASK_EXIT,abi::SYSTEM_TASK_YIELD,abi::SYSTEM_TASK_QOS_SET,
        abi::SYSTEM_SYNC_MUTEX_CREATE,abi::SYSTEM_SYNC_MUTEX_ACQUIRE,abi::SYSTEM_SYNC_MUTEX_RELEASE,
        abi::SYSTEM_HANDLE_CLOSE,abi::SYSTEM_CONSOLE_WRITE,
    ]);
    // First exercise the public create/recursive/unlock/close contract.
    let create=crate::rt_demo::run_program("rt3-create",USER_RING,10,calls);
    check(matches!(create,Some((Some(ProcState::Exited{code:0}),Some(0)))),"public mutex create contract");

    let pid=proc::create("rt3-inversion",calls).expect("RT3 process");
    let base=arch::USER_WINDOW.0;
    let entry=proc::load_elf(pid,USER_RING).expect("RT3 ELF");
    let handle=crate::user_mutex::create_for(pid).expect("RT3 mutex");
    let mut ids=[None;3];
    for (i,role) in [7u64,8,9].into_iter().enumerate() {
        let top=base+STACK_TOP_OFF-(i as u64)*STACK_PAGES*FRAME_SIZE;
        for page in 1..=STACK_PAGES {proc::map_new(pid,top-page*FRAME_SIZE,MapFlags::USER|MapFlags::WRITE).expect("RT3 stack");}
        ids[i]=proc::spawn_thread(pid,"rt3-user",entry,top,role,handle.raw()).ok();
    }
    LOW_TASK.store(ids[0].map_or(0,|id|id.0.0),Ordering::Relaxed);
    check(ids.iter().all(Option::is_some),"spawn three user tasks");
    sched::run();
    check(proc::state(pid)==Some(ProcState::Exited{code:0}),"three-task process exits cleanly");
    check(DONATED.load(Ordering::Relaxed)==1,"high task donates UserInitiated QoS to low holder");
    proc::reap(pid);kobj::run_cleanup(usize::MAX);
    let after=(kobj::stats(),crate::mm::frame::free_frames());
    check(after.0.0==baseline.0.0 && after.0.1==0 && after.1==baseline.1,"RT3 resources return to baseline");
    check(crate::ipc_demo::rt3_channel_inheritance(),"cross-process ring Channel roundtrip");
    check(IPC_DONATED.load(Ordering::Relaxed)==1,"ring client donates QoS to Channel service");
    kprintln!("[JSR-RT3] cpl3=true classic_inversion=true donated={} ipc_donated={} reclaimed={} failed={}",DONATED.load(Ordering::Relaxed),IPC_DONATED.load(Ordering::Relaxed),after.0.0==baseline.0.0&&after.1==baseline.1,FAILED.load(Ordering::Relaxed));
    FAILED.load(Ordering::Relaxed)
}
