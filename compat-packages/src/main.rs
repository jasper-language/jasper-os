//! Command-line frontend for verified compatibility component management.
//!
//! 提供验证安装、查看、回滚和卸载入口；组件执行由后续 Linux ABI 服务负责。

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use jasper_compat_packages::ComponentInstaller;

fn usage() -> ! {
    eprintln!(
        "usage:\n  jasper-compat-pkg install <root> <manifest> <archive>\n  jasper-compat-pkg current <root> <name>\n  jasper-compat-pkg rollback <root> <name>\n  jasper-compat-pkg uninstall <root> <name>"
    );
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        usage();
    }
    let command = args[1].as_str();
    let installer = ComponentInstaller::new(PathBuf::from(&args[2]));
    let result = match command {
        "install" if args.len() == 5 => installer
            .install(Path::new(&args[3]), Path::new(&args[4]))
            .map(|item| format!("{} {} {}", item.name, item.version, item.path.display())),
        "current" => installer
            .current(&args[3])
            .map(|item| format!("{} {} {}", item.name, item.version, item.path.display())),
        "rollback" => installer
            .rollback(&args[3])
            .map(|item| format!("{} {} {}", item.name, item.version, item.path.display())),
        "uninstall" => installer.uninstall(&args[3]).map(|_| "uninstalled".into()),
        _ => usage(),
    };
    match result {
        Ok(message) => println!("{message}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
