//! 在真实 P0 GPT 的 Control A/B 分区初始化启动控制记录。
//! Initializes boot-control records in the Control A/B partitions of a real P0 GPT.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_model::boot::{ControlBlock, Slot};
use jasper_lifecycle_staging::p0_control::P0ControlStore;
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: jasper-control-init <p0-image> <total-bytes> <system-image> <release> <transaction-id> <security-epoch> <schema-min> <schema-max>";

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 8 {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    }
    let image = PathBuf::from(&args[0]);
    let Some(total_bytes) = parse_u64(&args[1]) else {
        eprintln!("total-bytes must be a base-10 u64");
        return ExitCode::from(2);
    };
    let source = PathBuf::from(&args[2]);
    let Some(release) = parse_u64(&args[3]) else {
        eprintln!("release must be a base-10 u64");
        return ExitCode::from(2);
    };
    let Some(transaction_id) = parse_u64(&args[4]) else {
        eprintln!("transaction-id must be a base-10 u64");
        return ExitCode::from(2);
    };
    let Some(security_epoch) = parse_u64(&args[5]) else {
        eprintln!("security-epoch must be a base-10 u64");
        return ExitCode::from(2);
    };
    let Some(schema_min) = parse_u32(&args[6]) else {
        eprintln!("schema-min must be a base-10 u32");
        return ExitCode::from(2);
    };
    let Some(schema_max) = parse_u32(&args[7]) else {
        eprintln!("schema-max must be a base-10 u32");
        return ExitCode::from(2);
    };
    let digest = match digest_source(&source) {
        Ok(digest) => digest,
        Err(error) => {
            eprintln!("jasper-control-init: FAIL: {error}");
            return ExitCode::FAILURE;
        }
    };
    let block = match ControlBlock::initialize(
        Slot::A,
        release,
        digest,
        transaction_id,
        security_epoch,
        schema_min,
        schema_max,
    ) {
        Ok(block) => block,
        Err(error) => {
            eprintln!("jasper-control-init: FAIL: invalid control block: {error:?}");
            return ExitCode::FAILURE;
        }
    };
    match P0ControlStore::initialize(&image, total_bytes, block) {
        Ok(store) => {
            let current = store.current();
            println!(
                "jasper-control-init: PASS generation={} active={:?} release={} digest={}",
                current.generation(),
                current.active_slot(),
                release,
                hex(&digest)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-control-init: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_u64(value: &std::ffi::OsStr) -> Option<u64> {
    value.to_string_lossy().parse().ok()
}

fn parse_u32(value: &std::ffi::OsStr) -> Option<u32> {
    value.to_string_lossy().parse().ok()
}

fn digest_source(path: &PathBuf) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        hasher.update(&buffer[..count]);
    }
    if total == 0 {
        return Err(format!("{} is empty", path.display()));
    }
    Ok(hasher.finalize().into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
