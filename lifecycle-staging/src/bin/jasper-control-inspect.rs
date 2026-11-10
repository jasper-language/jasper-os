//! 从真实 P0 Control A/B 分区恢复并显示启动控制记录。
//! Recovers and displays boot-control records from real P0 Control A/B partitions.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_staging::p0_control::P0ControlStore;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(image) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-control-inspect <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Some(bytes) = args.next() else {
        eprintln!("usage: jasper-control-inspect <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = bytes.to_string_lossy().parse::<u64>() else {
        eprintln!("total-bytes must be a base-10 integer");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: jasper-control-inspect <p0-image> <total-bytes>");
        return ExitCode::from(2);
    }
    match P0ControlStore::open(&image, bytes) {
        Ok(store) => {
            let current = store.current();
            println!(
                "jasper-control-inspect: PASS generation={} transaction={} floor={} epoch={} active={:?} schema={}..={}",
                current.generation(),
                current.transaction_id(),
                current.rollback_floor(),
                current.security_epoch(),
                current.active_slot(),
                current.data_schema_range().0,
                current.data_schema_range().1
            );
            for (slot, record) in [
                ("A", current.slot(jasper_lifecycle_model::boot::Slot::A)),
                ("B", current.slot(jasper_lifecycle_model::boot::Slot::B)),
            ] {
                println!(
                    "jasper-control-inspect: slot={slot} state={:?} generation={} release={} attempts={} digest={} schema={}..={}",
                    record.state(),
                    record.generation(),
                    record.release(),
                    record.attempts(),
                    hex(&record.digest()),
                    record.data_schema_range().0,
                    record.data_schema_range().1
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-control-inspect: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
