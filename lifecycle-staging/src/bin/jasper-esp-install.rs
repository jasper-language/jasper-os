//! 把 UEFI 启动 FAT 分区内容安装到 P0 ESP。
//! Install UEFI boot-files from a FAT partition into the P0 ESP.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_lifecycle_staging::gpt_layout::install_uefi_esp;

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let Some(image) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-esp-install <p0-image> <total-bytes> <uefi-fat-image>");
        return ExitCode::from(2);
    };
    let Some(bytes) = args.next() else {
        eprintln!("usage: jasper-esp-install <p0-image> <total-bytes> <uefi-fat-image>");
        return ExitCode::from(2);
    };
    let Ok(bytes) = bytes.to_string_lossy().parse::<u64>() else {
        eprintln!("total-bytes must be a base-10 integer");
        return ExitCode::from(2);
    };
    let Some(source) = args.next().map(PathBuf::from) else {
        eprintln!("usage: jasper-esp-install <p0-image> <total-bytes> <uefi-fat-image>");
        return ExitCode::from(2);
    };
    if args.next().is_some() {
        eprintln!("usage: jasper-esp-install <p0-image> <total-bytes> <uefi-fat-image>");
        return ExitCode::from(2);
    }
    match install_uefi_esp(&image, bytes, &source) {
        Ok(receipt) => {
            println!(
                "jasper-esp-install: PASS bootloader_bytes={} kernel_bytes={} files={} directories={}",
                receipt.bootloader_bytes,
                receipt.kernel_bytes,
                receipt.files,
                receipt.directories
            );
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("jasper-esp-install: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
