//! Native guest acceptance for Sandbox launch plans.
#![no_std]
#![no_main]

use jasper_rt::{entry, ids, println, sys};
use kernel_core::sandbox::SandboxKey;
use kernel_core::sandbox_image::{
    ContentDigest, ImageLayerSpec, ImageVersion, SignedImage, MAX_IMAGE_LAYERS,
};
use kernel_core::sandbox_launch::{CapabilitySet, DataScopeGrant, DeviceGrant, LaunchResources};
use kernel_core::sandbox_launch_abi::{
    LaunchCreateArgs, CREATE_BYTES, INFO_BYTES, MAX_DATA_SCOPES, MAX_DEVICE_GRANTS,
};
use kernel_core::sandbox_storage_abi::{ImageAddArgs, IMAGE_ADD_BYTES};
use kernel_core::security_domain::DomainKey;
use kernel_core::workload::ResourceLimits;
use kernel_core::workload_abi::{CreateArgs, CREATE_BYTES as WORKLOAD_CREATE_BYTES};

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

fn digest(byte: u8) -> ContentDigest {
    ContentDigest::new([byte; 32]).expect("non-zero test digest")
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
        content: digest(0x31),
        bytes: 64,
    };
    let raw = ImageAddArgs {
        sandbox,
        spec: kernel_core::sandbox_image::ImageSpec {
            image: SignedImage {
                content: digest(0x11),
                signer: 7,
                signature: digest(0x22),
                version: ImageVersion {
                    major: 1,
                    minor: 0,
                    patch: 0,
                },
            },
            rootfs_bytes: 64,
            writable_bytes: 4096,
            max_volumes: 1,
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

fn create_plan(sandbox: SandboxKey, image_raw: u64) -> Result<u64, i32> {
    let image = kernel_core::sandbox_image::ImageKey::from_raw(image_raw).ok_or(13)?;
    let raw = LaunchCreateArgs {
        sandbox,
        root: None,
        image,
        volume: None,
        root_capabilities: CapabilitySet::EXECUTE
            .union(CapabilitySet::DATA_READ)
            .union(CapabilitySet::DATA_WRITE),
        capabilities: CapabilitySet::EXECUTE,
        resources: LaunchResources {
            limits: LIMITS,
            io_rate: None,
        },
        network_policy: None,
        device_count: 0,
        data_count: 0,
        devices: [EMPTY_DEVICE; MAX_DEVICE_GRANTS],
        data: [EMPTY_DATA; MAX_DATA_SCOPES],
    }
    .encode()
    .ok_or(14)?;
    debug_assert_eq!(raw.len(), CREATE_BYTES);
    let key = call(
        ids::SYSTEM_SANDBOX_LAUNCH_CREATE,
        raw.as_ptr() as u64,
        raw.len() as u64,
        0,
    );
    (key > 0).then_some(key as u64).ok_or(15)
}

fn query_plan(sandbox: SandboxKey, plan: u64, image: u64) -> Result<(), i32> {
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
        || u64::from_le_bytes(info[32..40].try_into().unwrap()) != image
    {
        return Err(17);
    }
    Ok(())
}

fn run() -> Result<(), i32> {
    let sandbox_raw = create_sandbox()?;
    let sandbox = SandboxKey::from_raw(sandbox_raw).ok_or(18)?;
    let image = load_image(sandbox)?;
    let plan = create_plan(sandbox, image)?;
    query_plan(sandbox, plan, image)?;
    if call(ids::SYSTEM_SANDBOX_LAUNCH_DESTROY, plan, 0, 0) != 0 {
        return Err(19);
    }
    let stale = call(ids::SYSTEM_SANDBOX_LAUNCH_QUERY, plan, 0, 0);
    if stale != -(ids::SYSTEM_SANDBOX_ERROR_NOT_FOUND as i64) {
        return Err(20);
    }
    if call(
        ids::SYSTEM_SANDBOX_IMAGE_DESTROY,
        sandbox.to_raw(),
        image,
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
        "sandbox-launch: ok sandbox=true image=true plan=true query=true destroy=true cleanup=true"
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
