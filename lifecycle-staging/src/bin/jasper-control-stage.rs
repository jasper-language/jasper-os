//! 将已校验系统映像登记为非活动 B 槽候选并持久提交。
//! Registers a verified system image as the inactive B-slot candidate and commits it.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_model::boot::{Candidate, Slot};
use jasper_lifecycle_staging::p0_control::P0ControlStore;
use sha2::{Digest, Sha256};

const USAGE: &str = "usage: jasper-control-stage <p0-image> <total-bytes> <system-image> <release> <transaction-id> <security-epoch> <schema-min> <schema-max>";

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
            eprintln!("jasper-control-stage: FAIL: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut store = match P0ControlStore::open(&image, total_bytes) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("jasper-control-stage: FAIL: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut next = store.current();
    if let Err(error) = next.stage_candidate(
        Slot::B,
        Candidate {
            release,
            digest,
            transaction_id,
            security_epoch,
            data_schema_min: schema_min,
            data_schema_max: schema_max,
        },
    ) {
        eprintln!("jasper-control-stage: FAIL: candidate rejected: {error:?}");
        return ExitCode::FAILURE;
    }
    match store.commit_next(next) {
        Ok(()) => {
            println!(
                "jasper-control-stage: PASS generation={} candidate=B release={} digest={}",
                next.generation(),
                release,
                hex(&digest)
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-control-stage: FAIL: {error}");
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
