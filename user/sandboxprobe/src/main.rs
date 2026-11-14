//! Native guest acceptance for Sandbox launch plans.
#![no_std]
#![no_main]

use jasper_rt::{entry, ids, println, sys};
use kernel_core::device::{Filter, Record, RECORD_SIZE};
use kernel_core::object::Rights;
use kernel_core::sandbox::SandboxKey;
use kernel_core::sandbox_image::{
    ContentDigest, ImageKey, ImageLayerSpec, ImageVersion, SignedImage, VolumeKey,
    MAX_IMAGE_LAYERS,
};
use kernel_core::sandbox_launch::{
    CapabilitySet, DataScopeGrant, DeviceGrant, LaunchResources, NetworkPolicyRef,
};
use kernel_core::sandbox_launch_abi::{
    LaunchCreateArgs, CREATE_BYTES, INFO_BYTES, MAX_DATA_SCOPES, MAX_DEVICE_GRANTS,
};
use kernel_core::sandbox_storage_abi::{
    ImageAddArgs, VolumeCreateArgs, IMAGE_ADD_BYTES, VOLUME_CREATE_BYTES,
};
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::ResourceLimits;
use kernel_core::workload_abi::{CreateArgs, CREATE_BYTES as WORKLOAD_CREATE_BYTES};
use sha2::{Digest as _, Sha256};

static SANDBOX_CHILD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/sandbox-child.elf"));

const LIMITS: ResourceLimits = ResourceLimits {
    cpu_permille: 100,
    memory_bytes: 64 * 1024,
    threads: 2,
    ring_entries: 8,
    io_bytes: 64 * 1024,
    io_ops: 64,
};

const EMPTY_DEVICE: DeviceGrant = DeviceGrant {
    object: 0,
    generation: 0,
    rights: 0,
    owner: DomainKey::NONE,
    grantee: DomainKey::NONE,
};
const EMPTY_DATA: DataScopeGrant = DataScopeGrant {
    object: 0,
    generation: 0,
    owner: DomainKey::NONE,
    grantee: DomainKey::NONE,
    writable: false,
};

fn call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { sys::call3(id, a, b, c) }
}

fn digest(bytes: &[u8]) -> ContentDigest {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    ContentDigest::new(digest).expect("non-zero content digest")
}

fn create_sandbox() -> Result<u64, i32> {
    let desc = CreateArgs {
        parent: None,
        limits: LIMITS,
    }
    .encode();
    debug_assert_eq!(desc.len(), WORKLOAD_CREATE_BYTES);
    let key = call(
        ids::SYSTEM_SANDBOX_CREATE,
        desc.as_ptr() as u64,
        desc.len() as u64,
        0,
    );
    (key > 0).then_some(key as u64).ok_or(10)
}

fn load_image(sandbox: SandboxKey) -> Result<u64, i32> {
    let mut layers = [ImageLayerSpec::default(); MAX_IMAGE_LAYERS];
    layers[0] = ImageLayerSpec {
        content: digest(SANDBOX_CHILD),
        bytes: SANDBOX_CHILD.len() as u64,
    };
    let raw = ImageAddArgs {
        sandbox,
        spec: kernel_core::sandbox_image::ImageSpec {
            image: SignedImage {
                content: digest(SANDBOX_CHILD),
                signer: 7,
                signature: digest(b"jasper-os sandbox launch acceptance"),
                version: ImageVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: SANDBOX_CHILD.len() as u64,
            writable_bytes: 4096,
            max_volumes: 2,
        },
        layer_count: 1,
        layers,
    }
    .encode()
    .expect("bounded image record");
    debug_assert_eq!(raw.len(), IMAGE_ADD_BYTES);
    let key = call(
        ids::SYSTEM_SANDBOX_IMAGE_LOAD,
        raw.as_ptr() as u64,
        raw.len() as u64,
        0,
    );
    if key <= 0 {
        return Err(11);
    }
    Ok(key as u64)
}

fn create_volume(sandbox: SandboxKey, image: ImageKey) -> Result<VolumeKey, i32> {
    let raw = VolumeCreateArgs {
        sandbox,
        image,
        capacity_bytes: 4096,
    }
    .encode();
    debug_assert_eq!(raw.len(), VOLUME_CREATE_BYTES);
    let key = call(
        ids::SYSTEM_SANDBOX_VOLUME_CREATE,
        raw.as_ptr() as u64,
        raw.len() as u64,
        0,
    );
    if key <= 0 {
        return Err(23);
    }
    VolumeKey::from_raw(key as u64).ok_or(24)
}

fn open_first_device() -> Result<i64, i32> {
    let mut records = [0u8; 4096];
    let required = call(
        ids::SYSTEM_DEVICE_LIST,
        u64::from(Filter::ALL.to_word()),
        records.as_mut_ptr() as u64,
        records.len() as u64,
    );
    if required < RECORD_SIZE as i64 || required as usize > records.len() {
        return Err(36);
    }
    let mut raw = [0u8; RECORD_SIZE];
    raw.copy_from_slice(&records[..RECORD_SIZE]);
    let device = Record::decode(&raw);
    let handle = call(
        ids::SYSTEM_DEVICE_OPEN,
        u64::from(device.bdf),
        Rights::READ.bits() as u64,
        0,
    );
    (handle > 0).then_some(handle).ok_or(37)
}

fn plan_record(
    sandbox: SandboxKey,
    image: ImageKey,
    volume: VolumeKey,
    data_volume: VolumeKey,
    device: Option<i64>,
    network_generation: Option<u32>,
) -> Option<[u8; CREATE_BYTES]> {
    let mut data = [EMPTY_DATA; MAX_DATA_SCOPES];
    data[0] = DataScopeGrant {
        object: data_volume.to_raw(),
        generation: (data_volume.to_raw() >> 16) as u32,
        owner: DomainKey::NONE,
        grantee: DomainKey::NONE,
        writable: true,
    };
    let mut devices = [EMPTY_DEVICE; MAX_DEVICE_GRANTS];
    let device_count = if let Some(handle) = device {
        devices[0] = DeviceGrant {
            object: handle as u64,
            generation: 0,
            rights: Rights::READ.bits(),
            owner: DomainKey::NONE,
            grantee: DomainKey::NONE,
        };
        1
    } else {
        0
    };
    let mut root_capabilities = CapabilitySet::EXECUTE
        .union(CapabilitySet::DATA_READ)
        .union(CapabilitySet::DATA_WRITE);
    let mut capabilities = CapabilitySet::EXECUTE.union(CapabilitySet::DATA_WRITE);
    if device.is_some() {
        root_capabilities = root_capabilities.union(CapabilitySet::DEVICE);
        capabilities = capabilities.union(CapabilitySet::DEVICE);
    }
    if network_generation.is_some() {
        root_capabilities = root_capabilities.union(CapabilitySet::NETWORK);
        capabilities = capabilities.union(CapabilitySet::NETWORK);
    }
    LaunchCreateArgs {
        sandbox,
        root: None,
        image,
        volume: Some(volume),
        root_capabilities,
        capabilities,
        resources: LaunchResources {
            limits: LIMITS,
            io_rate: None,
        },
        network_policy: network_generation.map(|generation| NetworkPolicyRef {
            policy: sandbox.to_raw(),
            generation,
        }),
        device_count,
        data_count: 1,
        devices,
        data,
    }
    .encode()
}

fn create_plan_call(
    sandbox: SandboxKey,
    image: ImageKey,
    volume: VolumeKey,
    data_volume: VolumeKey,
    device: Option<i64>,
    network_generation: Option<u32>,
) -> i64 {
    let Some(raw) = plan_record(
        sandbox,
        image,
        volume,
        data_volume,
        device,
        network_generation,
    ) else {
        return -(ids::SYSTEM_ERROR_INVALID_ARGUMENT as i64);
    };
    call(
        ids::SYSTEM_SANDBOX_LAUNCH_CREATE,
        raw.as_ptr() as u64,
        raw.len() as u64,
        0,
    )
}

fn create_plan(
    sandbox: SandboxKey,
    image: ImageKey,
    volume: VolumeKey,
    data_volume: VolumeKey,
    device: Option<i64>,
    network_generation: Option<u32>,
) -> Result<u64, i32> {
    let key = create_plan_call(
        sandbox,
        image,
        volume,
        data_volume,
        device,
        network_generation,
    );
    (key > 0).then_some(key as u64).ok_or(15)
}

fn query_plan(sandbox: SandboxKey, plan: u64, image: ImageKey, volume: VolumeKey) -> Result<(), i32> {
    let mut info = [0u8; INFO_BYTES];
    let result = call(
        ids::SYSTEM_SANDBOX_LAUNCH_QUERY,
        plan,
        info.as_mut_ptr() as u64,
        info.len() as u64,
    );
    if result != INFO_BYTES as i64 || &info[..4] != b"JSL1" {
        return Err(16);
    }
    if u64::from_le_bytes(info[8..16].try_into().unwrap()) != plan
        || u64::from_le_bytes(info[16..24].try_into().unwrap()) != sandbox.to_raw()
        || u64::from_le_bytes(info[32..40].try_into().unwrap()) != image.to_raw()
        || u64::from_le_bytes(info[40..48].try_into().unwrap()) != volume.to_raw()
        || u16::from_le_bytes(info[102..104].try_into().unwrap()) != 1
    {
        return Err(17);
    }
    Ok(())
}

fn start_plan(plan: u64, image: &[u8]) -> i64 {
    unsafe {
        sys::call3(
            ids::SYSTEM_SANDBOX_LAUNCH_START,
            plan,
            image.as_ptr() as u64,
            image.len() as u64,
        )
    }
}

fn run() -> Result<(), i32> {
    let sandbox_raw = create_sandbox()?;
    let sandbox = SandboxKey::from_raw(sandbox_raw).ok_or(18)?;
    let image = ImageKey::from_raw(load_image(sandbox)?).ok_or(13)?;
    let volume = create_volume(sandbox, image)?;
    let data_volume = create_volume(sandbox, image)?;
    let device = open_first_device()?;
    let device_plan = create_plan(sandbox, image, volume, data_volume, Some(device), None)?;
    query_plan(sandbox, device_plan, image, volume)?;
    if call(ids::SYSTEM_HANDLE_CLOSE, device as u64, 0, 0) != 0 {
        return Err(38);
    }
    let revoked_device = call(ids::SYSTEM_SANDBOX_LAUNCH_QUERY, device_plan, 0, 0);
    if revoked_device != -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64) {
        return Err(39);
    }
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, device_plan, 0, 0) != 0 {
        return Err(40);
    }

    let stale_network = create_plan_call(
        sandbox,
        image,
        volume,
        data_volume,
        None,
        Some(2),
    );
    if stale_network != -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64) {
        return Err(41);
    }
    let network_plan = create_plan(sandbox, image, volume, data_volume, None, Some(1))?;
    query_plan(sandbox, network_plan, image, volume)?;
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, network_plan, 0, 0) != 0 {
        return Err(42);
    }

    let invalid_plan = create_plan(sandbox, image, volume, data_volume, None, None)?;
    let invalid = start_plan(invalid_plan, &SANDBOX_CHILD[..SANDBOX_CHILD.len() - 1]);
    if invalid != -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64) {
        return Err(28);
    }
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, invalid_plan, 0, 0) != 0 {
        return Err(29);
    }

    let plan = create_plan(sandbox, image, volume, data_volume, None, None)?;
    query_plan(sandbox, plan, image, volume)?;
    let child = start_plan(plan, SANDBOX_CHILD);
    if child <= 0 {
        return Err(30);
    }
    if start_plan(plan, SANDBOX_CHILD) != -(ids::SYSTEM_SANDBOX_ERROR_STATE as i64) {
        return Err(35);
    }
    if call(ids::SYSTEM_PROCESS_WAIT, child as u64, 0, 0) != 0 {
        return Err(31);
    }
    if call(ids::SYSTEM_HANDLE_CLOSE, child as u64, 0, 0) != 0 {
        return Err(32);
    }
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, plan, 0, 0) != 0 {
        return Err(33);
    }
    let restarted = start_plan(plan, SANDBOX_CHILD);
    if restarted != -(ids::SYSTEM_SANDBOX_ERROR_NOT_FOUND as i64) {
        return Err(34);
    }

    let revoked_plan = create_plan(sandbox, image, volume, data_volume, None, None)?;
    query_plan(sandbox, revoked_plan, image, volume)?;
    if call(
        ids::SYSTEM_SANDBOX_VOLUME_DESTROY,
        sandbox.to_raw(),
        data_volume.to_raw(),
        0,
    ) != 0
    {
        return Err(26);
    }
    let revoked = call(ids::SYSTEM_SANDBOX_LAUNCH_QUERY, revoked_plan, 0, 0);
    if revoked != -(ids::SYSTEM_ERROR_RIGHTS_DENIED as i64) {
        return Err(27);
    }
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, revoked_plan, 0, 0) != 0 {
        return Err(19);
    }
    let stale = call(ids::SYSTEM_SANDBOX_LAUNCH_QUERY, revoked_plan, 0, 0);
    if stale != -(ids::SYSTEM_SANDBOX_ERROR_NOT_FOUND as i64) {
        return Err(20);
    }
    if call(
        ids::SYSTEM_SANDBOX_VOLUME_DESTROY,
        sandbox.to_raw(),
        volume.to_raw(),
        0,
    ) != 0
    {
        return Err(25);
    }
    if call(
        ids::SYSTEM_SANDBOX_IMAGE_DESTROY,
        sandbox.to_raw(),
        image.to_raw(),
        0,
    ) != 0
    {
        return Err(21);
    }
    if call(ids::SYSTEM_SANDBOX_STOP, sandbox.to_raw(), 0, 0) != 0
        || call(ids::SYSTEM_SANDBOX_STOP, sandbox.to_raw(), 0, 0) != 0
        || call(ids::SYSTEM_SANDBOX_DESTROY, sandbox.to_raw(), 0, 0) != 0
    {
        return Err(22);
    }
    println!(
        "sandbox-launch: ok sandbox=true image=true device_authority=true data_authority=true net_authority=true plan=true query=true child=true child_exit=0 child_cleanup=true destroy=true cleanup=true"
    );
    Ok(())
}

fn main(_: u64, _: u64) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(step) => {
            println!("sandbox-launch: FAIL step={step}");
            step
        }
    }
}

entry!(main);
