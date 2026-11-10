//! 为 P0 GPT 的 A/B 系统槽和 Data 分区创建 ext4。
//! Create ext4 filesystems for P0 GPT system A/B and data partitions.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_staging::gpt_layout::format_p0_ext4;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-ext4-provision <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Some(bytes) = args.next() else {
        eprintln!("usage: jasper-ext4-provision <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = bytes.to_string_lossy().parse::<u64>() else {
        eprintln!("total-bytes must be a base-10 integer");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: jasper-ext4-provision <p0-image> <total-bytes>");
        return ExitCode::from(2);
    }
    match format_p0_ext4(&path, bytes) {
        Ok(receipts) => {
            for receipt in receipts {
                println!(
                    "jasper-ext4-provision: PASS role={:?} start_lba={} sectors={} blocks={} uuid={} label={}",
                    receipt.role,
                    receipt.start_lba,
                    receipt.sectors,
                    receipt.blocks,
                    receipt.uuid,
                    receipt.volume_label
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-ext4-provision: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
