//! Native guest acceptance for the versioned installation ABI.
#![no_std]
#![no_main]

use jasper_rt::{entry, ids, println, sys};
use kernel_core::native_install::{
    GrantRights, InstallationKey, OwnerScope, PackageKey, PackageSource, PackageSpec, Subject,
    CONTENT_BYTES,
};
use kernel_core::native_install_abi::{
    GrantArgs, PackagePutArgs, RegisterArgs, GRANT_BYTES, INFO_BYTES, PACKAGE_PUT_BYTES,
    REGISTER_BYTES,
};

const PACKAGE_BYTES: &[u8] = b"native-install-abi";
const CONTENT: [u8; CONTENT_BYTES] = [0x49; CONTENT_BYTES];

fn call(id: u64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { sys::call3(id, a, b, c) }
}

fn put_package() -> Result<u64, i32> {
    let encoded = PackagePutArgs {
        spec: PackageSpec {
            app_id: 0x494e_5354_414c_4c31,
            publisher: 7,
            content: CONTENT,
            version: 1,
        },
        bytes_ptr: PACKAGE_BYTES.as_ptr() as u64,
        bytes_len: PACKAGE_BYTES.len() as u32,
    }
    .encode()
    .ok_or(10)?;
    debug_assert_eq!(encoded.len(), PACKAGE_PUT_BYTES);
    let key = call(
        ids::SYSTEM_INSTALL_PACKAGE_WRITE,
        encoded.as_ptr() as u64,
        encoded.len() as u64,
        0,
    );
    let again = call(
        ids::SYSTEM_INSTALL_PACKAGE_WRITE,
        encoded.as_ptr() as u64,
        encoded.len() as u64,
        0,
    );
    (key > 0 && again == key).then_some(key as u64).ok_or(11)
}

fn register(package: u64) -> Result<u64, i32> {
    let package = PackageKey::from_raw(package).ok_or(12)?;
    let encoded = RegisterArgs {
        package,
        scope: OwnerScope::System,
        source: PackageSource::SystemBuiltin,
        update_authority: Subject::System,
    }
    .encode();
    debug_assert_eq!(encoded.len(), REGISTER_BYTES);
    let key = call(
        ids::SYSTEM_INSTALL_REGISTRATION_CREATE,
        encoded.as_ptr() as u64,
        encoded.len() as u64,
        0,
    );
    (key > 0).then_some(key as u64).ok_or(13)
}

fn grant(installation: u64) -> Result<(), i32> {
    let encoded = GrantArgs {
        installation: InstallationKey::from_raw(installation).ok_or(14)?,
        subject: Subject::System,
        rights: GrantRights::DISCOVER.union(GrantRights::START),
        expires_at: None,
    }
    .encode();
    debug_assert_eq!(encoded.len(), GRANT_BYTES);
    let key = call(
        ids::SYSTEM_INSTALL_GRANT_CREATE,
        encoded.as_ptr() as u64,
        encoded.len() as u64,
        0,
    );
    (key > 0).then_some(()).ok_or(15)
}

fn query(installation: u64, package: u64) -> Result<(), i32> {
    let mut info = [0u8; INFO_BYTES];
    let result = call(
        ids::SYSTEM_INSTALL_QUERY,
        installation,
        info.as_mut_ptr() as u64,
        info.len() as u64,
    );
    if result != INFO_BYTES as i64 || &info[..4] != b"JSI1" {
        return Err(16);
    }
    if u64::from_le_bytes(info[8..16].try_into().unwrap()) != installation
        || u64::from_le_bytes(info[16..24].try_into().unwrap()) != package
        || info[41] != 1
    {
        return Err(17);
    }
    Ok(())
}

fn open_handle(installation: u64) -> Result<u64, i32> {
    let handle = call(ids::SYSTEM_INSTALL_HANDLE_CREATE, installation, 0, 0);
    (handle > 0).then_some(handle as u64).ok_or(19)
}

fn query_handle(handle: u64, installation: u64, package: u64) -> Result<(), i32> {
    let mut info = [0u8; INFO_BYTES];
    let result = call(
        ids::SYSTEM_INSTALL_HANDLE_QUERY,
        handle,
        info.as_mut_ptr() as u64,
        info.len() as u64,
    );
    if result != INFO_BYTES as i64 || &info[..4] != b"JSI1" {
        return Err(20);
    }
    if u64::from_le_bytes(info[8..16].try_into().unwrap()) != installation
        || u64::from_le_bytes(info[16..24].try_into().unwrap()) != package
        || info[41] != 1
    {
        return Err(21);
    }
    Ok(())
}

fn close(handle: u64) -> Result<(), i32> {
    (call(ids::SYSTEM_HANDLE_CLOSE, handle, 0, 0) == 0)
        .then_some(())
        .ok_or(22)
}

fn run() -> Result<(), i32> {
    let package = put_package()?;
    let installation = register(package)?;
    grant(installation)?;
    query(installation, package)?;
    let short = call(
        ids::SYSTEM_INSTALL_QUERY,
        installation,
        0,
        (INFO_BYTES - 1) as u64,
    );
    if short != -(ids::SYSTEM_ERROR_INVALID_ARGUMENT as i64) {
        return Err(18);
    }
    let handle = open_handle(installation)?;
    query_handle(handle, installation, package)?;
    let duplicate = call(
        ids::SYSTEM_HANDLE_DUPLICATE,
        handle,
        kernel_core::object::Rights::READ.bits() as u64,
        0,
    );
    if duplicate <= 0 {
        return Err(23);
    }
    close(handle)?;
    query_handle(duplicate as u64, installation, package)?;
    if call(ids::SYSTEM_HANDLE_RESTRICT, duplicate as u64, 0, 0) != 0 {
        return Err(24);
    }
    if call(
        ids::SYSTEM_INSTALL_HANDLE_QUERY,
        duplicate as u64,
        0,
        INFO_BYTES as u64,
    ) != -(ids::SYSTEM_HANDLE_ERROR_RIGHTS_DENIED as i64)
    {
        return Err(25);
    }
    close(duplicate as u64)?;
    if call(
        ids::SYSTEM_INSTALL_HANDLE_QUERY,
        duplicate as u64,
        0,
        INFO_BYTES as u64,
    ) != -(ids::SYSTEM_HANDLE_ERROR_INVALID as i64)
    {
        return Err(26);
    }
    println!(
        "native-install-abi: ok package=true idempotent=true register=true grant=true query=true handle=true rights=true close=true denied_short=true"
    );
    Ok(())
}

fn main(_: u64, _: u64) -> i32 {
    match run() {
        Ok(()) => 0,
        Err(step) => {
            println!("native-install-abi: FAIL step={step}");
            step
        }
    }
}

entry!(main);
