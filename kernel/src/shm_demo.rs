//! SHM-1 backing integration fixture (kernel callers, not CPL3 or cross-CPU proof). Author: chatgpt.
use core::sync::atomic::{AtomicBool,AtomicU64,Ordering};
use crate::{kobj, proc, kprintln, syscall::SyscallSet};
use kernel_core::{object::{ObjectType,Rights}, objtable::ObjId, paging::MapFlags};
fn check(ok: bool, what: &str) { assert!(ok, "SHM backing fixture: {}", what); }
pub fn run() -> u64 {
    crate::ipc_demo::s3_channel_roundtrip();
    concurrent_lifetimes();
    randomized_lifetimes();
    fixed_quota_exhaustion();
    private_page_lifetime();
    pin_metadata_failure();
    let before = crate::baseline::baseline();
    let a=proc::create("shm-a",SyscallSet::EMPTY).expect("SHM process a");
    let b=proc::create("shm-b",SyscallSet::EMPTY).expect("SHM process b");
    let va=crate::arch::USER_WINDOW.0+0x200000;
    let vb=va+0x10000;
    let h=proc::create_memory(a,2).expect("SHM create");
    check(proc::memory_quota(a).unwrap().mapped==2,"allocated pages charged");
    let frames=crate::mm::frame::free_frames();
    check(proc::create_memory(a,proc::MAX_PROCESS_FRAMES as u64)==Err(proc::ProcError::MemoryQuota),"total backing quota rejects individually valid object");
    check(crate::mm::frame::free_frames()==frames && proc::memory_quota(a).unwrap().mapped==2,"quota rejection is atomic");
    check(proc::create_memory(a,0).is_err(),"zero page object rejected");
    proc::map_memory(a,h,va,0,1,true).expect("SHM map a");
    let h_b=proc::transfer(a,h,b).expect("SHM transfer leaf");
    check(proc::handle_info(a,h).is_none(),"transfer removes sender handle");
    let object=proc::handle_info(b,h_b).unwrap().0;
    let id=ObjId::from_raw(object.id.0).unwrap();
    let ro=proc::grant(b,id,ObjectType::Memory,Rights::READ.union(Rights::MAP)).unwrap();
    proc::map_memory(b,ro,vb,0,1,false).expect("SHM read-only alias");
    check(proc::map_memory(b,ro,vb+0x1000,1,1,true).is_err(),"read-only handle cannot write map");
    check(!proc::page_flags(b,vb).unwrap().contains(MapFlags::WRITE),"read-only PTE");
    proc::write(a,va,&0x53484d3150414745u64.to_le_bytes()).unwrap();
    check(proc::read_u64(b,vb)==Some(0x53484d3150414745),"shared physical contents");
    check(proc::unmap_range(a,va,1).is_err(),"legacy unmap cannot free shared backing");
    check(proc::protect_range(b,vb,1,true,false).is_err(),"legacy protect cannot upgrade shared mapping");
    let pinned=kobj::with(|t| proc::pin_user_in(t,a,va,8,true)).expect("SHM pin");
    check(proc::memory_quota(a).unwrap().pinned==1,"actual pin charged");
    proc::unmap_memory(a,va,1).unwrap();
    check(proc::page_flags(a,va).is_none(),"PTE removed after revoke");
    check(proc::exit_idle(a,0),"creator exits with shared backing and pin alive");
    check(proc::reap(a).is_some(),"creator reap before peer");
    kobj::run_cleanup(usize::MAX);
    check(proc::exit_idle(b,0),"peer exit"); check(proc::reap(b).is_some(),"peer reap");
    kobj::run_cleanup(usize::MAX); // last Memory handle and alias are gone; pin alone retains page 0.
    let mut bytes=[0u8;8];
    check(pinned.read_at(0,&mut bytes) && u64::from_le_bytes(bytes)==0x53484d3150414745,"pin survives object close and both unmaps");
    check(pinned.write_at(0,&42u64.to_le_bytes()),"retained page write");
    drop(pinned);
    // Exercise reservation refusal/split/drop independently with a bounded real account.
    let account=crate::mm::memory_quota::Account::new().unwrap();
    let mut charge=account.reserve(2,1,2,1).unwrap();
    check(account.reserve(0,1,2,1).is_none(),"fixed reference quota refuses atomically");
    check(account.reserve(1,0,2,1).is_none(),"backing reservation quota refuses atomically");
    let page_charge=charge.take_page().unwrap();
    drop(charge);
    check(account.snapshot()==kernel_core::memory_object::Usage { mapped:1,pinned:0 },"split charge releases only its remainder");
    drop(page_charge);
    check(account.snapshot()==kernel_core::memory_object::Usage::default(),"all reservation credits returned");
    drop(account);
    let after=crate::baseline::baseline();
    check(before==after,"objects pending frames pins conserved");
    kprintln!("[JSR-SHM1-BACKING] shared=true rights=true transfer=true revoke=true pin_survives=true resources=true quota=true creator_exit=true failed=0");
    cross_cpu_revoke();
    shared_failure_isolation();
    0
}

static PROBE_PID:AtomicU64=AtomicU64::new(0);
static REVOKED_REMOTE:AtomicBool=AtomicBool::new(false);
pub fn record_revoke_targets(targets:kernel_core::smp::CpuSet) { REVOKED_REMOTE.store(targets.contains(1),Ordering::Release); }
fn revoke_controller() {
    check(crate::arch::cpu_index()==0,"revoke controller CPU0");
    let pid=ObjId::from_raw(PROBE_PID.load(Ordering::Acquire)).unwrap();
    let va=crate::arch::USER_WINDOW.0+0x200000;
    let end=crate::sched::timer_ticks()+1000;
    while proc::read_u64(pid,va+4096)!=Some(1) && crate::sched::timer_ticks()<end { crate::sched::sleep_ticks(1); }
    check(proc::read_u64(pid,va+4096)==Some(1),"remote user probe filled its TLB");
    proc::unmap_memory(pid,va,1).expect("cross CPU revoke");
    check(REVOKED_REMOTE.load(Ordering::Acquire),"actual revoke target set included CPU1");
    proc::write(pid,va+4096,&2u64.to_le_bytes()).unwrap();
}
fn cross_cpu_revoke() {
    if crate::smp::cpu_count()<2 {
        kprintln!("[JSR-SHM1-REVOKE] cpus=1 skipped=requires_remote_cpu"); return;
    }
    let before=crate::baseline::baseline();
    let fault_before=crate::fault::count();
    let pid=proc::create("shm-revoke",SyscallSet::EMPTY).unwrap();
    let va=crate::arch::USER_WINDOW.0+0x200000;
    let h=proc::create_memory(pid,2).unwrap();
    proc::map_memory(pid,h,va,0,2,true).unwrap();
    proc::write(pid,va,&0x53484d315245564fu64.to_le_bytes()).unwrap();
    PROBE_PID.store(pid.raw(),Ordering::Release); REVOKED_REMOTE.store(false,Ordering::Release);
    check(crate::ipc_demo::start_shm_revoke_probe(pid,va),"publish user probe on CPU1");
    let mut affinity=kernel_core::smp::CpuSet::EMPTY; affinity.insert(0);
    check(crate::sched::spawn_on(crate::task::TaskId(93001),"shm-revoker",revoke_controller,None,affinity).is_ok(),"publish controller CPU0");
    crate::sched::run();
    check(proc::state(pid)==Some(proc::ProcState::Exited { code:-1 }),"post-ack remote access faulted");
    check(crate::fault::count()==fault_before+1,"exactly one expected fault");
    let fault=crate::fault::last().unwrap();
    check(fault.kind==crate::fault::UserFaultKind::PageFault && fault.addr==va,"fault address is revoked shared view");
    check(proc::reap(pid).is_some(),"faulted process reap");
    check(crate::baseline::baseline()==before,"cross CPU revoke resources conserved");
    kprintln!("[JSR-SHM1-REVOKE] writer_cpu=0 reader_cpu=1 target_included=true post_ack_fault=true resources=true failed=0");
}

fn private_page_lifetime() {
    let before=crate::baseline::baseline();
    let p=proc::create("shm-private",SyscallSet::EMPTY).unwrap();
    let va=crate::arch::USER_WINDOW.0+0x200000;
    proc::map_anon(p,va,2,true).unwrap();
    proc::map_new(p,va+8192,MapFlags::USER|MapFlags::WRITE).unwrap(); // same page-storage path as ELF/stacks
    check(proc::memory_quota(p).unwrap().mapped==3,"anonymous and loader pages share ownership account");
    proc::write(p,va,&0x5052495641544531u64.to_le_bytes()).unwrap();
    let pin=kobj::with(|t|proc::pin_user_in(t,p,va,8,true)).unwrap();
    let orphan_before=crate::mm::pin::orphaned_total();
    proc::unmap_range(p,va,1).unwrap();
    check(proc::memory_quota(p).unwrap().mapped==3,"unmapped private page retained by pin charge");
    check(crate::mm::pin::stats().1==1 && crate::mm::pin::orphaned_total()==orphan_before+1,"existing detached-pin observation preserved");
    check(proc::exit_idle(p,0) && proc::reap(p).is_some(),"private process exits before pin");
    kobj::run_cleanup(usize::MAX);
    let mut bytes=[0u8;8];
    check(pin.read_at(0,&mut bytes) && u64::from_le_bytes(bytes)==0x5052495641544531,"private Memory page survives process teardown");
    drop(pin);
    check(crate::baseline::baseline()==before,"private reference resources conserved");
    kprintln!("[JSR-SHM1-PRIVATE] anonymous=true loader=true pin_after_exit=true resources=true failed=0");
}
fn fixed_quota_exhaustion() {
    let limit=proc::MAX_PROCESS_FRAMES;
    let mut held=alloc::vec::Vec::new(); held.try_reserve_exact(limit).unwrap();
    // Kernel heap arenas grow but do not shrink. First pass warms the exact live-pin allocation shape;
    // second pass must return all object/page/pin resources to its measured baseline with identical limits.
    for pass in 0..2 {
        let before=crate::baseline::baseline();
        let p=proc::create("shm-pin-quota",SyscallSet::EMPTY).unwrap();
        let va=crate::arch::USER_WINDOW.0+0x200000;
        proc::map_anon(p,va,1,true).unwrap();
        for _ in 0..limit { held.push(kobj::with(|t|proc::pin_user_in(t,p,va,8,true)).unwrap()); }
        check(proc::memory_quota(p).unwrap().pinned==limit as u64,"actual process fixed reference quota filled");
        let frames=crate::mm::frame::free_frames(); let pins=crate::mm::pin::stats();
        let extra=kobj::with(|t|proc::pin_user_in(t,p,va,8,true));
        check(matches!(extra,Err(proc::ProcError::MemoryQuota)),"one more actual pin refused");
        check(proc::memory_quota(p).unwrap().pinned==limit as u64 && crate::mm::frame::free_frames()==frames
            && crate::mm::pin::stats()==pins,"pin refusal leaves existing refs unchanged");
        held.clear();
        check(proc::memory_quota(p).unwrap().pinned==0,"all actual pin charges returned");
        check(proc::exit_idle(p,0) && proc::reap(p).is_some(),"pin quota process cleanup");
        let after=crate::baseline::baseline();
        check(after.objects==before.objects && after.pending==before.pending && after.pins==before.pins,"pin quota object/pin baseline");
        if pass==1 { check(after==before,"measured pin quota frame baseline"); }
    }
    kprintln!("[JSR-SHM1-PIN-QUOTA] live={} refused=true atomic=true returned=true resources=true warmup=1 measured=1 failed=0",limit);
}

static ROLLED_BACK:AtomicU64=AtomicU64::new(0);
pub fn record_mapping_rollback(pages:u64) { ROLLED_BACK.store(pages,Ordering::Release); }
fn shared_failure_isolation() {
    use crate::fault_inject::{FRAME,IPI_TIMEOUT};
    for case in 0..3 {
        let before=crate::baseline::baseline();
        let isolated_before=crate::mm::memory_object::quarantined_pages();
        let p=proc::create("shm-failure",SyscallSet::EMPTY).unwrap();
        let base=crate::arch::USER_WINDOW.0;
        let h=proc::create_memory(p,2).unwrap();
        if case==0 {
            let va=base+0x200000;
            proc::map_memory(p,h,va,0,1,true).unwrap();
            IPI_TIMEOUT.arm(0,1).unwrap();
            let result=proc::unmap_memory(p,va,1);
            IPI_TIMEOUT.disarm();
            check(result==Err(proc::MemError::Busy),"shared revoke uncertainty returns failure");
            check(proc::page_flags(p,va).is_none(),"uncertain revoke PTE already absent");
            check(proc::memory_quota(p).unwrap().mapped==2,"uncertain backing still charged to live creator");
        } else {
            // x86_64 fixture: first page uses an existing 2MiB leaf table, second needs a new one.
            proc::map_new(p,base+0x200000,MapFlags::USER|MapFlags::WRITE).unwrap();
            let va=base+0x3ff000;
            ROLLED_BACK.store(0,Ordering::Release);
            FRAME.arm(0,1).unwrap();
            if case==2 { IPI_TIMEOUT.arm(0,1).unwrap(); }
            let result=proc::map_memory(p,h,va,0,2,true);
            FRAME.disarm(); IPI_TIMEOUT.disarm();
            check(ROLLED_BACK.load(Ordering::Acquire)==1,"one actual page published before forced map allocation failure");
            check(result==Err(if case==1 {proc::MemError::OutOfMemory} else {proc::MemError::Busy}),"partial map rollback result");
            check(proc::page_flags(p,va).is_none() && proc::page_flags(p,va+4096).is_none(),"partial map leaves no PTE");
            check(proc::memory_quota(p).unwrap().mapped==3,"rollback does not alter retained object ownership quota");
        }
        check(proc::exit_idle(p,0) && proc::reap(p).is_some(),"failed mapping process cleanup");
        let after=crate::baseline::baseline();
        let isolated=(crate::mm::memory_object::quarantined_pages()-isolated_before) as usize;
        let expected=if case==1 {0} else {1};
        check(isolated==expected && after.free_frames+isolated==before.free_frames
            && after.objects==before.objects && after.pending==before.pending && after.pins==before.pins,
            "failure resources conserved with exact intentional quarantine");
        kprintln!("[JSR-SHM1-FAILURE] case={} isolated={} expected={} resources=true failed=0",case,isolated,expected);
    }
}

fn pin_metadata_failure() {
    let before=crate::baseline::baseline();
    let p=proc::create("shm-pin-metadata",SyscallSet::EMPTY).unwrap();
    let va=crate::arch::USER_WINDOW.0+0x200000;
    proc::map_anon(p,va,1,true).unwrap();
    crate::mm::pin::reset_empty_diagnostics();
    let frames=crate::mm::frame::free_frames(); let usage=proc::memory_quota(p).unwrap();
    // Segment Vec, page-ref Vec, then the physical diagnostic Vec allocation.
    crate::fault_inject::HEAP.arm(2,1).unwrap();
    let result=kobj::with(|t|proc::pin_user_in(t,p,va,8,true));
    crate::fault_inject::HEAP.disarm();
    check(matches!(result,Err(proc::ProcError::OutOfFrames)),"pin diagnostic metadata OOM reports failure");
    check(crate::mm::frame::free_frames()==frames && crate::mm::pin::stats()==(0,0)
        && proc::memory_quota(p)==Some(usage),"metadata refusal publishes no pin or quota change");
    let retry=kobj::with(|t|proc::pin_user_in(t,p,va,8,true)).unwrap(); drop(retry);
    check(proc::exit_idle(p,0) && proc::reap(p).is_some(),"metadata failure process cleanup");
    check(crate::baseline::baseline()==before,"metadata failure resources conserved");
    kprintln!("[JSR-SHM1-PIN-METADATA] refused=true atomic=true retry=true resources=true failed=0");
}

// S-3 serialized production API sequences. This does not claim parallel syscall coverage.
fn randomized_lifetimes() {
    const ROUNDS:usize=64;
    for pass in 0..2 {
        let before=crate::baseline::baseline();
        let mut seed=0x53485f5345435552u64;
        for round in 0..ROUNDS {
            let a=proc::create("s3-a",SyscallSet::EMPTY).unwrap();
            let b=proc::create("s3-b",SyscallSet::EMPTY).unwrap();
            let ids=[a,b];
            let va=crate::arch::USER_WINDOW.0+0x800000;
            let mut owner=0usize;
            let mut root=proc::create_memory(a,1).unwrap();
            let object=ObjId::from_raw(proc::handle_info(a,root).unwrap().0.id.0).unwrap();
            let ro=[proc::grant(a,object,ObjectType::Memory,Rights::READ.union(Rights::MAP)).unwrap(),
                    proc::grant(b,object,ObjectType::Memory,Rights::READ.union(Rights::MAP)).unwrap()];
            let mut mapped=[false;2];
            let mut pins=alloc::vec::Vec::with_capacity(16);
            for step in 0..16 {
                seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;
                let which=(seed as usize>>8)&1;
                match seed%6 {
                    0 => {
                        if mapped[which] { proc::unmap_memory(ids[which],va,1).unwrap(); }
                        else { proc::map_memory(ids[which],ro[which],va,0,1,false).unwrap(); }
                        mapped[which]=!mapped[which];
                    }
                    1 => {
                        let old=root;let old_owner=owner;owner^=1;
                        root=proc::transfer(ids[old_owner],old,ids[owner]).unwrap();
                        check(proc::handle_info(ids[old_owner],old).is_none(),"S3 moved root stale");
                    }
                    2 => {
                        check(proc::map_memory(ids[which],ro[which],va+0x2000,0,1,true).is_err(),"S3 RO write map refused");
                        check(proc::page_flags(ids[which],va+0x2000).is_none(),"S3 refused map publishes nothing");
                        check(proc::transfer(ids[which],ro[which],ids[which^1]).is_err(),"S3 no-transfer authority refused");
                        check(proc::handle_info(ids[which],ro[which]).is_some(),"S3 failed transfer retains handle");
                    }
                    3 if mapped[which] => {
                        pins.push(kobj::with(|t|proc::pin_user_in(t,ids[which],va,8,false)).unwrap());
                        check(kobj::with(|t|proc::pin_user_in(t,ids[which],va,8,true)).is_err(),"S3 RO pin cannot escalate");
                    }
                    4 => {
                        proc::map_memory(ids[owner],root,va+0x4000,0,1,true).unwrap();
                        let value=((round as u64)<<32)|step;
                        proc::write(ids[owner],va+0x4000,&value.to_le_bytes()).unwrap();
                        for i in 0..2 { if mapped[i] { check(proc::read_u64(ids[i],va)==Some(value),"S3 aliases coherent"); } }
                        proc::unmap_memory(ids[owner],va+0x4000,1).unwrap();
                    }
                    _ => { if !pins.is_empty() { pins.pop(); } }
                }
            }
            let first=(seed as usize)&1;
            check(proc::exit_idle(ids[first],0),"S3 first exit");proc::reap(ids[first]);
            kobj::run_cleanup(usize::MAX);
            for pin in &pins { let mut data=[0u8;8];check(pin.read_at(0,&mut data),"S3 pin survives first exit"); }
            check(proc::exit_idle(ids[first^1],0),"S3 second exit");proc::reap(ids[first^1]);
            kobj::run_cleanup(usize::MAX);
            for pin in &pins { let mut data=[0u8;8];check(pin.read_at(0,&mut data),"S3 pin survives both exits"); }
            drop(pins);kobj::run_cleanup(usize::MAX);
        }
        if pass==1 { check(before==crate::baseline::baseline(),"S3 randomized measured baseline"); }
    }
    kprintln!("[JSR-S3-SEQUENCE] rounds=64 steps=16 seed=53485f5345435552 warmup=1 measured=1 rights=true transfer=true pins=true exits=true resources=true failed=0");
}

static S3_A:AtomicU64=AtomicU64::new(0);
static S3_B:AtomicU64=AtomicU64::new(0);
static S3_ROOT:AtomicU64=AtomicU64::new(0);
static S3_READY:AtomicU64=AtomicU64::new(0);
static S3_MAP_ATTEMPTS:AtomicU64=AtomicU64::new(0);
static S3_PIN_ATTEMPTS:AtomicU64=AtomicU64::new(0);
fn s3_ids()->[ObjId;2] { [ObjId::from_raw(S3_A.load(Ordering::Acquire)).unwrap(),ObjId::from_raw(S3_B.load(Ordering::Acquire)).unwrap()] }
fn s3_barrier() { S3_READY.fetch_add(1,Ordering::AcqRel);while S3_READY.load(Ordering::Acquire)!=2 { core::hint::spin_loop(); } }
fn s3_mapper() {
    check(crate::arch::cpu_index()==0,"S3 mapper CPU0");
    let ids=s3_ids();let va=crate::arch::USER_WINDOW.0+0xa00000;
    let mut owner=0usize;let mut root=kernel_core::object::HandleId::from_raw(S3_ROOT.load(Ordering::Acquire));
    s3_barrier();
    for _ in 0..64 {
        S3_MAP_ATTEMPTS.fetch_add(1,Ordering::Relaxed);
        match proc::map_memory(ids[owner],root,va,0,1,false) {
            Ok(()) => {},
            Err(proc::MemError::AlreadyMapped|proc::MemError::Busy|proc::MemError::NoSuchProcess|proc::MemError::InvalidHandle) => {},
            Err(_) => check(false,"S3 unexpected concurrent map error"),
        }
        if let Ok(next)=proc::transfer(ids[owner],root,ids[owner^1]) { root=next;owner^=1; }
        crate::sched::yield_now();
    }
}
fn s3_revoker() {
    check(crate::arch::cpu_index()==1,"S3 revoker CPU1");
    let ids=s3_ids();let va=crate::arch::USER_WINDOW.0+0xa00000;
    s3_barrier();
    for step in 0..64 {
        for pid in ids {
            S3_PIN_ATTEMPTS.fetch_add(1,Ordering::Relaxed);
            let pin=kobj::with(|t|proc::pin_user_in(t,pid,va,8,false));
            let _=proc::unmap_memory(pid,va,1);
            if let Ok(pin)=pin { let mut bytes=[1u8;8];check(pin.read_at(0,&mut bytes) && bytes==[0;8],"S3 concurrent retained pin data"); }
        }
        if step==32 { check(proc::exit_idle(ids[0],0),"S3 concurrent first exit"); }
        crate::sched::yield_now();
    }
    check(proc::exit_idle(ids[1],0),"S3 concurrent second exit");
}
fn concurrent_lifetimes() {
    if crate::smp::cpu_count()<2 { kprintln!("[JSR-S3-CONCURRENT] cpus=1 skipped=requires_remote_cpu");return; }
    for pass in 0..2 {
        let before=crate::baseline::baseline();
        let a=proc::create("s3-race-a",SyscallSet::EMPTY).unwrap();let b=proc::create("s3-race-b",SyscallSet::EMPTY).unwrap();
        let va=crate::arch::USER_WINDOW.0+0xa00000;
        let root=proc::create_memory(a,1).unwrap();proc::map_memory(a,root,va,0,1,false).unwrap();
        let keeper=kobj::with(|t|proc::pin_user_in(t,a,va,8,false)).unwrap();
        S3_A.store(a.raw(),Ordering::Release);S3_B.store(b.raw(),Ordering::Release);S3_ROOT.store(root.raw(),Ordering::Release);
        S3_READY.store(0,Ordering::Release);S3_MAP_ATTEMPTS.store(0,Ordering::Release);S3_PIN_ATTEMPTS.store(0,Ordering::Release);
        let prev=crate::sched::set_preemption(false);
        check(crate::sched::spawn_on(crate::task::TaskId(94000),"s3-map",s3_mapper,None,kernel_core::smp::CpuSet::first(1)).is_ok(),"S3 publish mapper");
        let mut affinity=kernel_core::smp::CpuSet::EMPTY;affinity.insert(1);
        check(crate::sched::spawn_on(crate::task::TaskId(94001),"s3-revoke",s3_revoker,None,affinity).is_ok(),"S3 publish revoker");
        crate::sched::set_preemption(prev);crate::sched::run();
        check(S3_MAP_ATTEMPTS.load(Ordering::Relaxed)==64 && S3_PIN_ATTEMPTS.load(Ordering::Relaxed)==128,"S3 race attempted every operation");
        check(proc::state(a)==Some(proc::ProcState::Exited { code:0 }) && proc::state(b)==Some(proc::ProcState::Exited { code:0 }),"S3 race both processes exited");
        let mut data=[1;8];check(keeper.read_at(0,&mut data) && data==[0;8],"S3 keeper survives concurrent exits");
        check(proc::reap(a).is_some() && proc::reap(b).is_some(),"S3 race reaps");kobj::run_cleanup(usize::MAX);drop(keeper);
        if pass==1 {check(crate::baseline::baseline()==before,"S3 concurrent measured baseline");}
    }
    kprintln!("[JSR-S3-CONCURRENT] mapper_cpu=0 revoker_cpu=1 map_attempts=64 pin_attempts=128 warmup=1 measured=1 exits=true retained=true resources=true failed=0");
}
