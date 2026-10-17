// jasper-xtask —— 宿主侧镜像构建器（verified: used by scripts/accept.sh）
// Builds a bootable BIOS disk image from the kernel ELF.
// Copied from the verified early prototype.

fn main() {
    let kernel = std::env::args().nth(1).expect("kernel elf path");
    let out = std::env::args().nth(2).expect("out image path");
    bootloader::BiosBoot::new(std::path::Path::new(&kernel))
        .create_disk_image(std::path::Path::new(&out))
        .expect("create_disk_image");
    let sz = std::fs::metadata(&out).map(|m| m.len()).unwrap_or(0);
    println!("wrote {out} ({sz} bytes)");
}
