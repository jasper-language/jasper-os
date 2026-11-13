//! Handle-backed authority for one native installation registration.
//!
//! The handle names an installation key only. It does not carry a logical
//! path, AppID or implicit launch/update authority. Discovery remains checked
//! by the install service against the authenticated caller.
//!
//! 原生安装登记句柄。句柄只命名稳定 InstallationKey，不携带逻辑路径、
//! AppID 或隐含的启动/更新授权；发现权仍由安装服务依据认证调用者检查。

use kernel_core::native_install::InstallationKey;
use kernel_core::object::{HandleId, ObjectType, Rights};
use kernel_core::objtable::ObjId;

use crate::kobj::{self, KObject};
use crate::proc::{self, ProcError};

/// The complete rights ceiling for an installation handle.
pub(crate) const INSTALLATION_HANDLE_RIGHTS: Rights = Rights::READ.union(Rights::DUPLICATE);

/// Leaf object containing only the stable installation key.
pub struct InstallationObj {
    installation: InstallationKey,
}

/// Mint one bounded installation handle for `pid` after the ABI layer has
/// checked discovery authority for the exact key.
pub(crate) fn create(pid: ObjId, installation: InstallationKey) -> Result<HandleId, ProcError> {
    proc::grant_new(
        pid,
        KObject::Installation(InstallationObj { installation }),
        ObjectType::Installation,
        INSTALLATION_HANDLE_RIGHTS,
    )
}

/// Resolve one installation handle with the requested rights. The returned key
/// is copied only after the live handle, type and exact object generation pass.
pub(crate) fn key(
    pid: ObjId,
    handle: HandleId,
    rights: Rights,
) -> Result<InstallationKey, ProcError> {
    kobj::with(|table| {
        let id = proc::resolve_in(table, pid, handle, ObjectType::Installation, rights)?;
        match table.get(id) {
            Ok(KObject::Installation(object)) => Ok(object.installation),
            _ => Err(ProcError::BadApp),
        }
    })
}
