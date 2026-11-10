//! 创建并回读一个空白 P0 GPT 映像。
//! Create and verify one empty P0 GPT image.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_staging::gpt_layout::create_p0_gpt;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-gpt-image <new-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Some(bytes) = args.next() else {
        eprintln!("usage: jasper-gpt-image <new-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = bytes.to_string_lossy().parse::<u64>() else {
        eprintln!("total-bytes must be a base-10 integer");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: jasper-gpt-image <new-image> <total-bytes>");
        return ExitCode::from(2);
    }
    match create_p0_gpt(&path, bytes) {
        Ok(receipt) => {
            println!(
                "jasper-gpt-image: PASS sectors={} partitions={} disk_guid={}",
                receipt.total_sectors, receipt.partitions, receipt.disk_guid
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-gpt-image: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
