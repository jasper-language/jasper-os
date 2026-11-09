//! Language-neutral USI v1 records.
//!
//! The kernel returns one response header followed by fixed-width records. The
//! human CLI and the structured client decode the same bytes and call the same
//! system operations.

pub const MAGIC: u32 = 0x4953_554a; // "JUSI" little-endian.
pub const VERSION: u16 = 1;
pub const HEADER_BYTES: usize = 24;
pub const INFO_BYTES: usize = 32;
pub const PROCESS_BYTES: usize = 32;
pub const MODULE_BYTES: usize = 48;
pub const MAX_PROFILE_NAME: usize = 12;
pub const MAX_MODULE_NAME: usize = 24;
pub const MAX_MODULE_VERSION: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum Service {
    Info = 1,
    ProcessList = 2,
    ModuleList = 3,
    ModuleLifecycle = 4,
    TimeNow = 5,
}

impl Service {
    pub const fn name(self) -> &'static str {
        match self {
            Service::Info => "system.info.get",
            Service::ProcessList => "system.process.list",
            Service::ModuleList => "system.module.list",
            Service::ModuleLifecycle => "system.module.lifecycle",
            Service::TimeNow => "system.time.now",
        }
    }

    pub const fn from_raw(value: u16) -> Option<Self> {
        match value {
            1 => Some(Service::Info),
            2 => Some(Service::ProcessList),
            3 => Some(Service::ModuleList),
            4 => Some(Service::ModuleLifecycle),
            5 => Some(Service::TimeNow),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub request_id: u64,
    pub service: Service,
    pub payload_bytes: u32,
    pub records: u32,
}

impl Header {
    pub const fn new(
        request_id: u64,
        service: Service,
        payload_bytes: u32,
        records: u32,
    ) -> Self {
        Self {
            request_id,
            service,
            payload_bytes,
            records,
        }
    }

    pub fn encode(self) -> [u8; HEADER_BYTES] {
        let mut out = [0u8; HEADER_BYTES];
        put_u32(&mut out, 0, MAGIC);
        put_u16(&mut out, 4, VERSION);
        put_u16(&mut out, 6, self.service as u16);
        put_u64(&mut out, 8, self.request_id);
        put_u32(&mut out, 16, self.payload_bytes);
        put_u32(&mut out, 20, self.records);
        out
    }

    pub fn decode(bytes: &[u8; HEADER_BYTES]) -> Option<Self> {
        if get_u32(bytes, 0) != MAGIC || get_u16(bytes, 4) != VERSION {
            return None;
        }
        let service = Service::from_raw(get_u16(bytes, 6))?;
        let records = get_u32(bytes, 20);
        let record_bytes = match service {
            Service::Info => INFO_BYTES,
            Service::ProcessList => PROCESS_BYTES,
            Service::ModuleList | Service::ModuleLifecycle => MODULE_BYTES,
            Service::TimeNow => return None,
        };
        if records.checked_mul(record_bytes as u32)? != get_u32(bytes, 16) {
            return None;
        }
        Some(Self {
            request_id: get_u64(bytes, 8),
            service,
            payload_bytes: get_u32(bytes, 16),
            records,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Info {
    pub abi: u64,
    pub online_cpus: u16,
    pub modules: u16,
    pub processes: u16,
    pub capabilities: u16,
    pub profile_name_len: u16,
    pub profile_name: [u8; MAX_PROFILE_NAME],
}

impl Info {
    pub fn profile_name(&self) -> &[u8] {
        &self.profile_name[..self.profile_name_len as usize]
    }

    pub fn encode(self) -> [u8; INFO_BYTES] {
        let mut out = [0u8; INFO_BYTES];
        put_u64(&mut out, 0, self.abi);
        put_u16(&mut out, 8, self.online_cpus);
        put_u16(&mut out, 10, self.modules);
        put_u16(&mut out, 12, self.processes);
        put_u16(&mut out, 14, self.capabilities);
        put_u16(&mut out, 16, self.profile_name_len);
        out[20..].copy_from_slice(&self.profile_name);
        out
    }

    pub fn decode(bytes: &[u8; INFO_BYTES]) -> Option<Self> {
        let len = get_u16(bytes, 16) as usize;
        if len > MAX_PROFILE_NAME {
            return None;
        }
        let mut profile_name = [0u8; MAX_PROFILE_NAME];
        profile_name.copy_from_slice(&bytes[20..]);
        Some(Self {
            abi: get_u64(bytes, 0),
            online_cpus: get_u16(bytes, 8),
            modules: get_u16(bytes, 10),
            processes: get_u16(bytes, 12),
            capabilities: get_u16(bytes, 14),
            profile_name_len: len as u16,
            profile_name,
        })
    }
}

pub const PROCESS_RUNNING: u8 = 0;
pub const PROCESS_EXITING: u8 = 1;
pub const PROCESS_EXITED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process {
    pub pid: u64,
    pub app: u32,
    pub state: u8,
    pub flags: u8,
    pub threads_live: u16,
    pub threads_total: u32,
    pub exit_code: i64,
}

impl Process {
    pub fn encode(self) -> [u8; PROCESS_BYTES] {
        let mut out = [0u8; PROCESS_BYTES];
        put_u64(&mut out, 0, self.pid);
        put_u32(&mut out, 8, self.app);
        out[12] = self.state;
        out[13] = self.flags;
        put_u16(&mut out, 14, self.threads_live);
        put_u32(&mut out, 16, self.threads_total);
        put_u64(&mut out, 24, self.exit_code as u64);
        out
    }

    pub fn decode(bytes: &[u8; PROCESS_BYTES]) -> Option<Self> {
        let state = bytes[12];
        (state <= PROCESS_EXITED).then_some(Self {
            pid: get_u64(bytes, 0),
            app: get_u32(bytes, 8),
            state,
            flags: bytes[13],
            threads_live: get_u16(bytes, 14),
            threads_total: get_u32(bytes, 16),
            exit_code: get_u64(bytes, 24) as i64,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Module {
    pub name: [u8; MAX_MODULE_NAME],
    pub version: [u8; MAX_MODULE_VERSION],
    pub order: u16,
    pub state: u8,
    pub health: u8,
    pub effective_health: u8,
    pub available: u8,
    pub name_len: u8,
    pub version_len: u8,
}

impl Module {
    pub fn from_parts(
        name: &str,
        version: &str,
        order: u16,
        state: u8,
        health: u8,
        effective_health: u8,
        available: bool,
    ) -> Option<Self> {
        if name.len() > MAX_MODULE_NAME || version.len() > MAX_MODULE_VERSION {
            return None;
        }
        let mut name_bytes = [0u8; MAX_MODULE_NAME];
        let mut version_bytes = [0u8; MAX_MODULE_VERSION];
        name_bytes[..name.len()].copy_from_slice(name.as_bytes());
        version_bytes[..version.len()].copy_from_slice(version.as_bytes());
        Some(Self {
            name: name_bytes,
            version: version_bytes,
            order,
            state,
            health,
            effective_health,
            available: u8::from(available),
            name_len: name.len() as u8,
            version_len: version.len() as u8,
        })
    }

    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn version(&self) -> &[u8] {
        &self.version[..self.version_len as usize]
    }

    pub fn encode(self) -> [u8; MODULE_BYTES] {
        let mut out = [0u8; MODULE_BYTES];
        out[..MAX_MODULE_NAME].copy_from_slice(&self.name);
        out[24..32].copy_from_slice(&self.version);
        put_u16(&mut out, 32, self.order);
        out[34] = self.state;
        out[35] = self.health;
        out[36] = self.effective_health;
        out[37] = self.available;
        out[38] = self.name_len;
        out[39] = self.version_len;
        out
    }

    pub fn decode(bytes: &[u8; MODULE_BYTES]) -> Option<Self> {
        if bytes[38] as usize > MAX_MODULE_NAME || bytes[39] as usize > MAX_MODULE_VERSION {
            return None;
        }
        let mut name = [0u8; MAX_MODULE_NAME];
        let mut version = [0u8; MAX_MODULE_VERSION];
        name.copy_from_slice(&bytes[..MAX_MODULE_NAME]);
        version.copy_from_slice(&bytes[24..32]);
        Some(Self {
            name,
            version,
            order: get_u16(bytes, 32),
            state: bytes[34],
            health: bytes[35],
            effective_health: bytes[36],
            available: bytes[37],
            name_len: bytes[38],
            version_len: bytes[39],
        })
    }
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_records_round_trip() {
        let header = Header::new(7, Service::ProcessList, 64, 2).encode();
        assert_eq!(Header::decode(&header), Some(Header::new(7, Service::ProcessList, 64, 2)));

        let info = Info {
            abi: 3,
            online_cpus: 4,
            modules: 9,
            processes: 2,
            capabilities: 10,
            profile_name_len: 8,
            profile_name: *b"headless\0\0\0\0",
        };
        assert_eq!(Info::decode(&info.encode()), Some(info));

        let process = Process {
            pid: 2,
            app: 0x5157,
            state: PROCESS_RUNNING,
            flags: 0,
            threads_live: 1,
            threads_total: 1,
            exit_code: 0,
        };
        assert_eq!(Process::decode(&process.encode()), Some(process));

        let module = Module::from_parts("core", "1.0.0", 0, 3, 1, 1, true).unwrap();
        assert_eq!(Module::decode(&module.encode()), Some(module));
    }

    #[test]
    fn malformed_headers_and_truncation_are_rejected() {
        let mut header = Header::new(1, Service::Info, 32, 1).encode();
        header[0] ^= 1;
        assert_eq!(Header::decode(&header), None);
        let mut service = Header::new(1, Service::Info, 32, 1).encode();
        service[6] = 0xff;
        assert_eq!(Header::decode(&service), None);
        let mut module = Module::from_parts("core", "1.0.0", 0, 3, 1, 1, true)
            .unwrap()
            .encode();
        module[38] = 25;
        assert_eq!(Module::decode(&module), None);
    }
}
