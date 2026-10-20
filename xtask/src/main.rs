// jasper-xtask —— 宿主侧工具（verified: used by scripts/accept.sh）
// Host-side tools for jasper-os images.
//
// 用法 / Usage:
//   xtask <kernel-elf> <out-image>
//       由内核 ELF 生成可引导的 BIOS 磁盘镜像（x86_64）。Build a bootable BIOS disk image.
//   xtask bootcap <in-elf> <out-elf> [objects=N] [tasks=N] [rt=N] [record=corrupt]
//       改写内核镜像里的启动容量记录（不重新编译即可以不同容量启动）；未给出的项不覆盖。
//       只检查语法，不检查取值范围：越界值由内核在启动期拒绝，这正是要验收的行为。
//       `record=corrupt` 写入一份版本号错误的记录，用来验收「记录损坏 ⇒ 拒绝启动」。
//       Patch the boot-capacity record in a kernel ELF; range checks are the kernel's job at boot.

use kernel_core::capacity::{self, Overrides, RECORD_LEN, RECORD_MAGIC};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("bootcap") {
        if let Err(e) = bootcap(&args[1..]) {
            eprintln!("xtask bootcap: {e}");
            std::process::exit(1);
        }
        return;
    }
    let kernel = args.first().expect("kernel elf path");
    let out = args.get(1).expect("out image path");
    bootloader::BiosBoot::new(std::path::Path::new(kernel))
        .create_disk_image(std::path::Path::new(out))
        .expect("create_disk_image");
    let sz = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    println!("wrote {out} ({sz} bytes)");
}

/// 在镜像里定位启动容量记录：标记必须恰好出现一次（出现多次就无法确定哪一份是内核真正读取的那份）。
fn locate(image: &[u8]) -> Result<usize, String> {
    let hits: Vec<usize> = image.windows(RECORD_MAGIC.len()).enumerate().filter(|(_, w)| *w == RECORD_MAGIC).map(|(i, _)| i).collect();
    match hits.as_slice() {
        [one] if one + RECORD_LEN <= image.len() => Ok(*one),
        [] => Err("镜像里没有启动容量记录（标记未找到）".into()),
        [_] => Err("启动容量记录被截断".into()),
        many => Err(format!("启动容量记录标记出现了 {} 次，无法确定位置", many.len())),
    }
}

fn bootcap(args: &[String]) -> Result<(), String> {
    let (input, output) = match args {
        [i, o, ..] => (i, o),
        _ => return Err("用法：xtask bootcap <in-elf> <out-elf> [objects=N] [tasks=N] [rt=N] [record=corrupt]".into()),
    };
    let mut image = std::fs::read(input).map_err(|e| format!("读取 {input} 失败：{e}"))?;
    let at = locate(&image)?;
    let mut record = [0u8; RECORD_LEN];
    record.copy_from_slice(&image[at..at + RECORD_LEN]);
    let mut ov: Overrides = capacity::parse(&record).map_err(|e| format!("镜像里现有的记录已损坏：{}", e.as_str()))?;
    let mut corrupt = false;
    for kv in &args[2..] {
        let (k, v) = kv.split_once('=').ok_or_else(|| format!("参数应为 名=值：{kv}"))?;
        if k == "record" && v == "corrupt" {
            corrupt = true;
            continue;
        }
        let n: u32 = v.parse().map_err(|_| format!("{k} 的取值不是十进制整数：{v}"))?;
        let n = if n == 0 { None } else { Some(n) };
        match k {
            "objects" => ov.objects = n,
            "tasks" => ov.tasks = n,
            "rt" => ov.rt = n,
            _ => return Err(format!("未知参数：{k}（可用：objects / tasks / rt / record）")),
        }
    }
    let mut new = capacity::encode(ov);
    if corrupt {
        new[8] = new[8].wrapping_add(1); // 版本号错误
    }
    image[at..at + RECORD_LEN].copy_from_slice(&new);
    std::fs::write(output, &image).map_err(|e| format!("写入 {output} 失败：{e}"))?;
    println!(
        "bootcap: {output} offset={at:#x} objects={:?} tasks={:?} rt={:?}{}",
        ov.objects,
        ov.tasks,
        ov.rt,
        if corrupt { " record=corrupt" } else { "" }
    );
    Ok(())
}
