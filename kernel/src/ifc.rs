//! Kernel bridge for SEC-5 information-flow control.

use core::sync::atomic::{AtomicU64, Ordering};

use kernel_core::ifc::{
    DeclassGrant, DeclassRoot, FlowChannel, FlowDecision, FlowEngine, FlowError, FlowIdentity,
    FlowLabel, FlowPolicy, PURPOSE_SYSTEM, TaintSet,
};
use kernel_core::security::SecurityContext;

use crate::sync::IrqSpinLock;

static FLOWS: IrqSpinLock<FlowEngine<256, 256>> = IrqSpinLock::new(FlowEngine::new());
static ALLOWED: AtomicU64 = AtomicU64::new(0);
static DENIED: AtomicU64 = AtomicU64::new(0);
static OVERFLOW: AtomicU64 = AtomicU64::new(0);
static LAST_DIGEST: AtomicU64 = AtomicU64::new(0);

pub fn identity(context: SecurityContext) -> FlowIdentity {
    FlowIdentity {
        object: context.object.object_id,
        generation: context.object.generation,
    }
}

fn ensure(
    engine: &mut FlowEngine<256, 256>,
    context: SecurityContext,
) -> Result<FlowIdentity, FlowError> {
    let secrecy = context.mac.secrecy().ok_or(FlowError::InvalidLabel)?;
    let id = identity(context);
    if !engine.contains(id) {
        engine.register(id, FlowLabel::for_secrecy(secrecy))?;
    }
    engine.set_policy(id, FlowPolicy::for_clearance(secrecy))?;
    Ok(id)
}

fn flush(engine: &mut FlowEngine<256, 256>) {
    let (allowed, denied, overflow, digest) = engine.drain_audit();
    ALLOWED.store(allowed, Ordering::Relaxed);
    DENIED.store(denied, Ordering::Relaxed);
    OVERFLOW.store(overflow, Ordering::Relaxed);
    LAST_DIGEST.store(digest, Ordering::Relaxed);
}

pub fn configure_label(
    context: SecurityContext,
    label: FlowLabel,
) -> Result<FlowIdentity, FlowError> {
    let mut engine = FLOWS.lock();
    let id = ensure(&mut engine, context)?;
    engine.set_label(id, label)?;
    Ok(id)
}

pub fn authorize_ipc(source: SecurityContext, sink: SecurityContext) -> Result<(), FlowError> {
    let mut engine = FLOWS.lock();
    let result = (|| {
        let source = ensure(&mut engine, source)?;
        let sink = ensure(&mut engine, sink)?;
        match engine.authorize(
            source,
            sink,
            FlowChannel::Ipc,
            PURPOSE_SYSTEM,
            crate::sched::now_ns(),
        )? {
            FlowDecision::Allowed => Ok(()),
            FlowDecision::Denied => Err(FlowError::Denied),
        }
    })();
    flush(&mut engine);
    result
}

pub fn declassify(
    context: SecurityContext,
    remove_data: TaintSet,
    remove_control: TaintSet,
    purpose: u32,
    expires_at: u64,
) -> Result<FlowLabel, FlowError> {
    let mut engine = FLOWS.lock();
    let result = (|| {
        let source = ensure(&mut engine, context)?;
        let grant: DeclassGrant = engine.mint_declass_grant(
            DeclassRoot::BOOTSTRAP,
            source,
            remove_data,
            remove_control,
            purpose,
            expires_at,
        )?;
        engine.declassify(source, grant, crate::sched::now_ns())
    })();
    flush(&mut engine);
    result
}

pub fn stats() -> (u64, u64, u64, u64) {
    (
        ALLOWED.load(Ordering::Relaxed),
        DENIED.load(Ordering::Relaxed),
        OVERFLOW.load(Ordering::Relaxed),
        LAST_DIGEST.load(Ordering::Relaxed),
    )
}

pub fn active_nodes() -> usize {
    FLOWS.lock().node_count()
}

pub fn release(object: u64, generation: u32) {
    let identity = FlowIdentity { object, generation };
    let mut engine = FLOWS.lock();
    let _ = engine.unregister(identity);
    flush(&mut engine);
}

#[cfg(feature = "sec5-verify")]
pub fn authorize_for_evidence(
    source: SecurityContext,
    sink: SecurityContext,
    channel: FlowChannel,
    purpose: u32,
    now: u64,
) -> Result<FlowDecision, FlowError> {
    let mut engine = FLOWS.lock();
    let result = (|| {
        let source = ensure(&mut engine, source)?;
        let sink = ensure(&mut engine, sink)?;
        engine.authorize(source, sink, channel, purpose, now)
    })();
    flush(&mut engine);
    result
}
