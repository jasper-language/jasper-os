//! Issue #42 M01: bridge real domain service producers to kernel EventSource.
//!
//! This is verification plumbing, not a new user ABI. Each producer snapshot is
//! copied into a normal kernel EventSource only after the domain state mutation
//! has committed.

use kernel_core::driver_host::{DriverHostBroker, QuiesceProof};
use kernel_core::fs::{PersistentIdentity};
use kernel_core::fs_prod::{FileQuota, FileSecurityLabel, ProductionFileGate};
use kernel_core::mac::{
    MacEffect, MacPolicy, MacPolicyPackage, MacRule,
    PolicyDigest, PolicySignature, PolicySignatureVerifier, PolicySource, Secrecy,
};
use kernel_core::net4_runtime::{UdpAddress, UdpLimits, UdpQuota};
use kernel_core::net4_service::WireGuardService;
use kernel_core::objtable::ObjId;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::security::{IdentityClass, SecurityDomain};
use kernel_core::service_events::{self, ServiceKind, Source as ServiceSource};
use kernel_core::subscription::{Delivery, Policy, Snapshot};
use kernel_core::virtio_gpu::{GpuPolicy, VirtioGpuBackend};
use kernel_core::wireguard::{testing::DeterministicRng, Config, StaticSecret};

use crate::subscription::{self, Read};
use crate::{kobj, proc, syscall::SyscallSet};

struct Bridge {
    source: ObjId,
    capability: HandleId,
    subscription: HandleId,
    version: u64,
}

struct Allow;

impl PolicySignatureVerifier for Allow {
    fn verify(
        &self,
        _: PolicySource,
        _: PolicyDigest,
        _: PolicySignature,
    ) -> bool {
        true
    }
}

fn event_identity(kind: ServiceKind, object: u64) -> service_events::Identity {
    service_events::Identity::new(kind, object, 1).unwrap()
}

fn bridge(pid: ObjId, producer: &ServiceSource) -> Bridge {
    let source = kobj::with(|t| subscription::create_publisher_in(t, producer.snapshot())).unwrap();
    let capability = proc::grant(
        pid,
        source,
        ObjectType::EventSource,
        Rights::SUBSCRIBE,
    )
    .unwrap();
    let (subscription, initial) =
        subscription::subscribe(pid, capability, Policy::Events).unwrap();
    assert_eq!(initial, Snapshot { version: 0, value: producer.snapshot().value });
    Bridge {
        source,
        capability,
        subscription,
        version: initial.version,
    }
}

fn forward(bridge: &mut Bridge, producer: &ServiceSource) {
    let committed = producer.snapshot();
    assert_eq!(committed.version, bridge.version + 1);
    let before = kobj::with(|t| subscription::snapshot_in(t, bridge.source)).unwrap();
    kobj::with(|t| subscription::publish_value_in(t, bridge.source, committed.value, committed.value))
        .unwrap();
    let after = kobj::with(|t| subscription::snapshot_in(t, bridge.source)).unwrap();
    assert_eq!(after.version, before.version + 1);
    assert_eq!(after.value, committed.value);
    bridge.version = committed.version;
}

fn publish(pid: ObjId, bridge: &mut Bridge, producer: &ServiceSource) {
    forward(bridge, producer);
    let after = kobj::with(|t| subscription::snapshot_in(t, bridge.source)).unwrap();
    assert_eq!(
        subscription::take(pid, bridge.subscription).unwrap(),
        Read::Data(Delivery::Event(kernel_core::subscription::Event {
            first: after.version,
            last: after.version,
            value: after.value,
        }))
    );
}

fn finish(pid: ObjId, bridge: Bridge) {
    proc::close_handle_for(pid, bridge.subscription).unwrap();
    proc::close_handle_for(pid, bridge.capability).unwrap();
    kobj::with(|t| subscription::finish_publisher_in(t, bridge.source));
}

fn file_policy() -> MacPolicy {
    const SOURCE: PolicySource = PolicySource {
        authority_id: 1,
        version: 1,
    };
    let mut package = MacPolicyPackage::empty(SOURCE);
    package
        .push(MacRule::new(
            SecurityDomain::USER,
            SecurityDomain::USER,
            &[MacEffect::Read, MacEffect::Write, MacEffect::Control],
            &[IdentityClass::KernelObject],
        ))
        .unwrap();
    package.seal_digest();
    MacPolicy::compile_verified(package, SOURCE, &Allow).unwrap()
}

fn file_gate() -> (ProductionFileGate<2, 4>, PersistentIdentity) {
    let mut gate = ProductionFileGate::<2, 4>::new(
        file_policy(),
        FileQuota::new(8, 8, 2),
        event_identity(ServiceKind::File, 0x4201),
    )
    .unwrap();
    let file = PersistentIdentity::new(1, 2, 0);
    gate.register(
        file,
        FileSecurityLabel::standard(Secrecy::Public),
    )
    .unwrap();
    (gate, file)
}

fn driver_broker() -> DriverHostBroker<1, 1, 1, 1> {
    DriverHostBroker::new_with_events(event_identity(ServiceKind::DriverHost, 0x4203)).unwrap()
}

fn network_service() -> WireGuardService {
    let mut keys = DeterministicRng::new(0x4d30_315f_4556_454e);
    let local = StaticSecret::generate(&mut keys).unwrap();
    let peer = StaticSecret::generate(&mut keys).unwrap();
    WireGuardService::new_with_events(
        Config::new(local, peer.public_key()),
        UdpAddress::new([10, 42, 0, 1], 51820),
        UdpAddress::new([10, 42, 0, 2], 51820),
        UdpQuota::new(1, 1, 1200),
        UdpLimits::new(1, 1, 1200),
        event_identity(ServiceKind::Network, 0x4202),
    )
    .unwrap()
}

fn graphics_backend() -> VirtioGpuBackend {
    VirtioGpuBackend::new_with_events(
        GpuPolicy::single_display(800, 600, 4, 4 * 1024 * 1024).unwrap(),
        event_identity(ServiceKind::Graphics, 0x4204),
    )
    .unwrap()
}

pub fn run() {
    for pass in 0..2 {
        let before = crate::baseline::baseline();
        let pid = proc::create("evt2-service-bridge", SyscallSet::EMPTY).unwrap();

        let (mut gate, file) = file_gate();
        let mut file_bridge = bridge(pid, gate.event_source());
        assert_eq!(
            gate.revoke(file, 2),
            Err(kernel_core::fs_prod::FileSecurityError::StaleGeneration)
        );
        assert_eq!(subscription::take(pid, file_bridge.subscription).unwrap(), Read::Empty);
        gate.revoke(file, 1).unwrap();
        publish(pid, &mut file_bridge, gate.event_source());

        let mut network = network_service();
        let mut network_bridge = bridge(pid, network.event_source().unwrap());
        network.close().unwrap();
        publish(pid, &mut network_bridge, network.event_source().unwrap());
        assert!(network.close().is_err());
        assert_eq!(subscription::take(pid, network_bridge.subscription).unwrap(), Read::Empty);

        let mut driver = driver_broker();
        let mut driver_bridge = bridge(pid, driver.event_source().unwrap());
        let mut host = driver.register_host().unwrap();
        assert_eq!(
            driver.reset(
                host,
                QuiesceProof {
                    dma_quiesced: false,
                    irq_quiesced: true,
                }
            ),
            Err(kernel_core::driver_host::Error::NotQuiesced)
        );
        assert_eq!(subscription::take(pid, driver_bridge.subscription).unwrap(), Read::Empty);
        host = driver.reset(host, QuiesceProof::CLEAN).unwrap().token;
        publish(pid, &mut driver_bridge, driver.event_source().unwrap());
        for _ in 0..17 {
            host = driver.reset(host, QuiesceProof::CLEAN).unwrap().token;
            forward(&mut driver_bridge, driver.event_source().unwrap());
        }
        assert!(matches!(
            subscription::take(pid, driver_bridge.subscription).unwrap(),
            Read::Data(Delivery::Resync(_))
        ));

        let mut graphics = graphics_backend();
        let mut graphics_bridge = bridge(pid, graphics.event_source().unwrap());
        graphics.reset();
        publish(pid, &mut graphics_bridge, graphics.event_source().unwrap());

        finish(pid, file_bridge);
        finish(pid, network_bridge);
        finish(pid, driver_bridge);
        finish(pid, graphics_bridge);
        kobj::run_cleanup(usize::MAX);
        assert_eq!(
            proc::subscription_quota(pid).unwrap(),
            kernel_core::memory_object::Usage::default()
        );

        assert!(proc::exit_idle(pid, 0));
        assert!(proc::reap(pid).is_some());
        kobj::run_cleanup(usize::MAX);
        let after = crate::baseline::baseline();
        if pass == 1 {
            assert_eq!(before, after);
            crate::kprintln!(
                "[JSR-EVT2-SERVICE] domains=4 fs=true net=true driver=true graphics=true failure_atomic=true overflow_resync=true subscriptions_closed=true resources=true failed=0"
            );
        }
    }
}
