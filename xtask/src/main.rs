// jasper-xtask —— 宿主侧工具（verified: used by scripts/accept.sh）
// Host-side tools for jasper-os images.
//
// 用法 / Usage:
//   xtask <kernel-elf> <out-image>
//       由内核 ELF 生成可引导的 BIOS 磁盘镜像（x86_64）。Build a bootable BIOS disk image.
//   xtask uefi <kernel-elf> <out-image>
//       Build an OVMF/UEFI GPT boot image; the default command remains BIOS.
//   xtask uefi-esp <kernel-elf> <out-fat-image>
//       Build the bootable UEFI FAT partition without an outer MBR/GPT.
//   xtask uefi-managed-esp <kernel-a> <kernel-b> <boot-manager> <out-fat-image>
//       Build a P0 A/B FAT partition managed by the Jasper UEFI selector.
//   xtask bootcap <in-elf> <out-elf> [objects=N] [tasks=N] [rt=N] [record=corrupt]
//       改写内核镜像里的启动容量记录（不重新编译即可以不同容量启动）；未给出的项不覆盖。
//       只检查语法，不检查取值范围：越界值由内核在启动期拒绝，这正是要验收的行为。
//       `record=corrupt` 写入一份版本号错误的记录，用来验收「记录损坏 ⇒ 拒绝启动」。
//       Patch the boot-capacity record in a kernel ELF; range checks are the kernel's job at boot.
//   xtask abi-contract generate|check
//       生成当前 ABI 版本的不可变契约快照，或校验当前源码与全部 ABI 快照。
//       Generate one immutable ABI contract snapshot or check the complete snapshot set.

use kernel_core::capacity::{self, Overrides, RECORD_LEN, RECORD_MAGIC};
use std::io::Write as _;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("abi-contract") {
        if let Err(e) = abi_contract(&args[1..]) {
            eprintln!("xtask abi-contract: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.first().map(String::as_str) == Some("bootcap") {
        if let Err(e) = bootcap(&args[1..]) {
            eprintln!("xtask bootcap: {e}");
            std::process::exit(1);
        }
        return;
    }
    if args.first().map(String::as_str) == Some("uefi-esp") {
        let kernel = args.get(1).expect("kernel elf path");
        let out = args.get(2).expect("out FAT image path");
        bootloader::DiskImageBuilder::new(std::path::PathBuf::from(kernel))
            .create_uefi_fat_partition(std::path::Path::new(out))
            .expect("UEFI FAT partition");
        let size = std::fs::metadata(out)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        println!("wrote {out} ({size} bytes)");
        return;
    }
    if args.first().map(String::as_str) == Some("uefi-managed-esp") {
        if let Err(error) = managed_uefi_esp(&args[1..]) {
            eprintln!("xtask uefi-managed-esp: {error}");
            std::process::exit(1);
        }
        return;
    }
    let uefi = args.first().map(String::as_str) == Some("uefi");
    let args = if uefi { &args[1..] } else { &args[..] };
    let kernel = args.first().expect("kernel elf path");
    let out = args.get(1).expect("out image path");
    if uefi {
        bootloader::UefiBoot::new(std::path::Path::new(kernel))
            .create_disk_image(std::path::Path::new(out))
            .expect("UEFI image");
    } else {
        bootloader::BiosBoot::new(std::path::Path::new(kernel))
            .create_disk_image(std::path::Path::new(out))
            .expect("BIOS image");
    }
    let sz = std::fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    println!("wrote {out} ({sz} bytes)");
}

fn managed_uefi_esp(args: &[String]) -> Result<(), String> {
    let [kernel_a, kernel_b, manager, output] = args else {
        return Err(
            "usage: xtask uefi-managed-esp <kernel-a> <kernel-b> <boot-manager> <out-fat-image>"
                .into(),
        );
    };
    let kernel_a = std::fs::read(kernel_a).map_err(|error| format!("read slot A: {error}"))?;
    let kernel_b = std::fs::read(kernel_b).map_err(|error| format!("read slot B: {error}"))?;
    let manager = std::fs::read(manager).map_err(|error| format!("read boot manager: {error}"))?;
    if kernel_a.is_empty() || kernel_b.is_empty() || manager.is_empty() {
        return Err("managed ESP inputs must be non-empty".into());
    }

    let output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("create {output}: {error}"))?;
    output_file
        .set_len(64 * 1024 * 1024)
        .map_err(|error| format!("size {output}: {error}"))?;
    fatfs::format_volume(
        output_file,
        fatfs::FormatVolumeOptions::new()
            .bytes_per_sector(512)
            .total_sectors(131_072)
            .fat_type(fatfs::FatType::Fat32)
            .fats(2)
            .volume_label(*b"JASPER ESP "),
    )
    .map_err(|error| format!("format {output}: {error}"))?;

    let output_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(output)
        .map_err(|error| format!("reopen {output}: {error}"))?;
    let filesystem = fatfs::FileSystem::new(output_file, fatfs::FsOptions::new())
        .map_err(|error| format!("open {output}: {error}"))?;
    let root = filesystem.root_dir();
    root.create_dir("efi")
        .map_err(|error| format!("create EFI directory: {error}"))?;
    root.create_dir("efi/boot")
        .map_err(|error| format!("create EFI boot directory: {error}"))?;
    root.create_dir("slots")
        .map_err(|error| format!("create slots directory: {error}"))?;
    root.create_dir("slots/a")
        .map_err(|error| format!("create slot A directory: {error}"))?;
    root.create_dir("slots/b")
        .map_err(|error| format!("create slot B directory: {error}"))?;
    write_fat_file(&root, "efi/boot/bootx64.efi", &manager)?;
    write_fat_file(&root, "slots/a/kernel-x86_64", &kernel_a)?;
    write_fat_file(&root, "slots/b/kernel-x86_64", &kernel_b)?;
    drop(root);
    filesystem
        .unmount()
        .map_err(|error| format!("close {output}: {error}"))?;
    let file = std::fs::File::open(output).map_err(|error| format!("reopen {output}: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("flush {output}: {error}"))?;
    println!(
        "wrote {output} ({} bytes, slot_a={} slot_b={} manager={})",
        64 * 1024 * 1024,
        kernel_a.len(),
        kernel_b.len(),
        manager.len()
    );
    Ok(())
}

fn write_fat_file(
    root: &fatfs::Dir<std::fs::File>,
    path: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let mut file = root
        .create_file(path)
        .map_err(|error| format!("create FAT file {path}: {error}"))?;
    file.truncate()
        .and_then(|_| file.write_all(bytes))
        .and_then(|_| file.flush())
        .map_err(|error| format!("write FAT file {path}: {error}"))
}

/// 在镜像里定位启动容量记录：标记必须恰好出现一次（出现多次就无法确定哪一份是内核真正读取的那份）。
fn locate(image: &[u8]) -> Result<usize, String> {
    let hits: Vec<usize> = image
        .windows(RECORD_MAGIC.len())
        .enumerate()
        .filter(|(_, w)| *w == RECORD_MAGIC)
        .map(|(i, _)| i)
        .collect();
    match hits.as_slice() {
        [one] if one + RECORD_LEN <= image.len() => Ok(*one),
        [] => Err("镜像里没有启动容量记录（标记未找到）".into()),
        [_] => Err("启动容量记录被截断".into()),
        many => Err(format!(
            "启动容量记录标记出现了 {} 次，无法确定位置",
            many.len()
        )),
    }
}

fn bootcap(args: &[String]) -> Result<(), String> {
    let (input, output) = match args {
        [i, o, ..] => (i, o),
        _ => return Err(
            "用法：xtask bootcap <in-elf> <out-elf> [objects=N] [tasks=N] [rt=N] [record=corrupt]"
                .into(),
        ),
    };
    let mut image = std::fs::read(input).map_err(|e| format!("读取 {input} 失败：{e}"))?;
    let at = locate(&image)?;
    let mut record = [0u8; RECORD_LEN];
    record.copy_from_slice(&image[at..at + RECORD_LEN]);
    let mut ov: Overrides =
        capacity::parse(&record).map_err(|e| format!("镜像里现有的记录已损坏：{}", e.as_str()))?;
    let mut corrupt = false;
    for kv in &args[2..] {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| format!("参数应为 名=值：{kv}"))?;
        if k == "record" && v == "corrupt" {
            corrupt = true;
            continue;
        }
        let n: u32 = v
            .parse()
            .map_err(|_| format!("{k} 的取值不是十进制整数：{v}"))?;
        let n = if n == 0 { None } else { Some(n) };
        match k {
            "objects" => ov.objects = n,
            "tasks" => ov.tasks = n,
            "rt" => ov.rt = n,
            _ => {
                return Err(format!(
                    "未知参数：{k}（可用：objects / tasks / rt / record）"
                ))
            }
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

/// 仓库根目录：xtask 位于 `<root>/xtask`，因此构建期路径不依赖调用者的 cwd。
/// Repository root, independent of the caller's current working directory.
fn repo_root() -> Result<std::path::PathBuf, String> {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(std::path::Path::to_path_buf)
        .ok_or_else(|| "无法定位仓库根目录".to_string())
}

/// 读取 `abi/abi-version.txt` 的当前版本。
fn native_version(root: &std::path::Path) -> Result<kernel_core::abi_version::AbiVersion, String> {
    let path = root.join("abi/abi-version.txt");
    let text =
        std::fs::read_to_string(&path).map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    kernel_core::abi_version::parse_source(&text)
        .map_err(|e| format!("解析 {} 失败：{e:?}", path.display()))
}

/// 从当前登记表与源码常量渲染规范快照。
fn render_current(root: &std::path::Path) -> Result<String, String> {
    let path = root.join("abi/system-ids.txt");
    let registry =
        std::fs::read_to_string(&path).map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
    let mut output = String::new();
    kernel_core::abi_contract::render_current(&registry, &mut output)
        .map_err(|e| format!("渲染 ABI 契约失败：{e:?}"))?;
    Ok(output)
}

/// 读取 `<root>/abi/snapshots/*.contract`，按路径稳定排序。
fn read_snapshots(
    root: &std::path::Path,
) -> Result<Vec<(kernel_core::abi_version::AbiVersion, String)>, String> {
    let dir = root.join("abi/snapshots");
    let entries =
        std::fs::read_dir(&dir).map_err(|e| format!("读取 {} 失败：{e}", dir.display()))?;
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|s| s.to_str()) == Some("contract"))
        .collect();
    paths.sort();
    let mut snapshots = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("读取 {} 失败：{e}", path.display()))?;
        let version = kernel_core::abi_contract::snapshot_version(&text)
            .map_err(|e| format!("{} 的世代头不合法：{e:?}", path.display()))?;
        let expected = format!(
            "{}.{}.{}.contract",
            version.major, version.minor, version.patch
        );
        if path.file_name().and_then(|s| s.to_str()) != Some(expected.as_str()) {
            return Err(format!(
                "{} 的 `abi=` 是 {}.{}.{}，文件名必须是 {}",
                path.display(),
                version.major,
                version.minor,
                version.patch,
                expected
            ));
        }
        snapshots.push((version, text));
    }
    Ok(snapshots)
}

fn check_snapshots(root: &std::path::Path, current: &str) -> Result<(), String> {
    let owned = read_snapshots(root)?;
    let refs: Vec<kernel_core::abi_contract::Snapshot<'_>> = owned
        .iter()
        .map(|(version, text)| kernel_core::abi_contract::Snapshot {
            version: *version,
            text,
        })
        .collect();
    kernel_core::abi_contract::check_snapshot_set(current, &refs)
        .map_err(|e| format!("ABI 契约门槛失败：{e:?}"))
}

/// `abi-contract generate|check`：快照一旦存在就不可覆盖；版本变化必须新增文件。
fn abi_contract(args: &[String]) -> Result<(), String> {
    let action = args
        .first()
        .map(String::as_str)
        .ok_or_else(|| "用法：xtask abi-contract generate|check".to_string())?;
    let root = repo_root()?;
    let current = render_current(&root)?;
    let version = native_version(&root)?;
    let dir = root.join("abi/snapshots");
    std::fs::create_dir_all(&dir).map_err(|e| format!("创建 {} 失败：{e}", dir.display()))?;
    let path = dir.join(format!(
        "{}.{}.{}.contract",
        version.major, version.minor, version.patch
    ));
    match action {
        "generate" => {
            match std::fs::read_to_string(&path) {
                Ok(existing) if existing == current => {
                    println!("ABI 快照已是最新：{}", path.display());
                }
                Ok(_) => {
                    return Err(format!(
                        "拒绝覆盖不可变快照 {}；契约变化必须提升 ABI 版本并新建快照",
                        path.display()
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    std::fs::write(&path, &current)
                        .map_err(|e| format!("写入 {} 失败：{e}", path.display()))?;
                    println!("写入 ABI 快照：{}", path.display());
                }
                Err(e) => return Err(format!("读取 {} 失败：{e}", path.display())),
            }
            check_snapshots(&root, &current)?;
        }
        "check" => check_snapshots(&root, &current)?,
        _ => return Err("用法：xtask abi-contract generate|check".to_string()),
    }
    println!(
        "ABI contract check: PASS ({}.{}.{})",
        version.major, version.minor, version.patch
    );
    Ok(())
}
