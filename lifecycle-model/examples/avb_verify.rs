//! Verify one Android v4 boot image and print Jasper-consumable firmware facts.
//! 验证一个 Android v4 启动镜像并输出 Jasper 可消费的固件事实。

use std::env;
use std::fs;
use std::process::ExitCode;

use jasper_lifecycle_model::android_firmware::verify_android_boot_image;

fn hex(bytes: &[u8]) {
    for byte in bytes {
        print!("{byte:02x}");
    }
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: avb_verify IMAGE [PARTITION]");
        return ExitCode::from(64);
    };
    let partition = args.next().unwrap_or_else(|| "boot".into());
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("avb-verify: read {path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    match verify_android_boot_image(&bytes, &partition) {
        Ok(firmware) => {
            print!(
                "avb-verify: PASS partition={partition} version=4 kernel_size={} \
                 original_image_size={} rollback_index={} signer_sha256=",
                firmware.boot.kernel_size(),
                firmware.boot.original_image_size(),
                firmware.vbmeta.rollback_index()
            );
            hex(&firmware.vbmeta.signer_fingerprint());
            print!(" content_sha256=");
            hex(&firmware.content_digest);
            println!();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("avb-verify: FAIL: {error}");
            ExitCode::FAILURE
        }
    }
}
