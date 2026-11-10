//! 在 P0 GPT 的 ESP 分区内创建 FAT32。
//! Create FAT32 inside the ESP partition of a P0 GPT image.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_staging::gpt_layout::format_esp_fat32;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(path) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-esp-format <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Some(bytes) = args.next() else {
        eprintln!("usage: jasper-esp-format <p0-image> <total-bytes>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = bytes.to_string_lossy().parse::<u64>() else {
        eprintln!("total-bytes must be a base-10 integer");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: jasper-esp-format <p0-image> <total-bytes>");
        return ExitCode::from(2);
    }
    match format_esp_fat32(&path, bytes) {
        Ok(receipt) => {
            println!(
                "jasper-esp-format: PASS start_lba={} sectors={} fat={:?} label={}",
                receipt.start_lba, receipt.sectors, receipt.fat_type, receipt.volume_label
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-esp-format: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
