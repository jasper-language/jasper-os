//! jasopack：宿主侧 `.jaso` 工具。
//! Host-side `.jaso` tool.
//!
//! ```text
//! jasopack pack <ELF> <清单文件> <指令集> <装载阶段> <输出>   打包（指令集：x86_64|aarch64|riscv64|riscv32；阶段：runtime|boot|build）
//! jasopack inspect <.jaso>                                   校验并列出头部、清单、各镜像（平台、段、导出、重定位数）、扩展与签名；
//!                                                            拒绝时输出稳定错误码（如 `rejected: image.wx (605) WriteExecute`）
//! jasopack migrate <format 0 文件> <输出>                       把 format 0 文件一次性迁移为 format 1（未签名；需要时再 sign）
//! jasopack sign <.jaso> <私钥种子文件> <输出>                  以发布者私钥（32 字节种子文件）签名（替换已有签名）
//! jasopack hybrid <.jaso> <jasper.import 文本> <输出>         把 Native 文件转成带绑定的 Hybrid 文件（未签名；绑定与清单须一致，SPEC §9.4）
//! jasopack pubkey <私钥种子文件>                              输出该私钥对应的公钥（十六进制，写进受信发布者表）
//! jasopack vectors <目录>                                    重建一致性向量（SPEC §14）：写出 `<名>.jaso` / `<名>.expect` 与开发用公钥，
//!                                                            逐个复核判定结果，删除目录中多余的旧向量
//! jasopack conform <.jaso>                                   按一致性上下文判定一个文件，输出 `ok` 或码名（与 `.expect` 同格式）
//! ```
//! 退出码：0 成功；1 输入不合法（校验或打包失败）；2 用法错误或读写失败。

use std::process::ExitCode;

use jaso::{Arch, Jaso, Stage, FLAG_R, FLAG_W, FLAG_X};

fn hybrid(input: &str, import: &str, out: &str) -> ExitCode {
    let (bytes, text) = match (std::fs::read(input), std::fs::read(import)) {
        (Ok(b), Ok(t)) => (b, t),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("读取输入失败：{}", e);
            return ExitCode::from(2);
        }
    };
    match jaso::pack::to_hybrid(&bytes, &text) {
        Ok(h) => match std::fs::write(out, h) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("写入 {} 失败：{}", out, e);
                ExitCode::from(2)
            }
        },
        Err(e) => {
            println!("rejected: {}", e);
            ExitCode::from(1)
        }
    }
}

fn usage() -> ExitCode {
    eprintln!(
        "用法：jasopack pack <ELF> <清单文件> <指令集> <装载阶段> <输出>\n      jasopack inspect <.jaso>\n      \
         jasopack migrate <format 0 文件> <输出>\n      \
         jasopack sign <.jaso> <私钥种子文件> <输出>\n      jasopack hybrid <.jaso> <jasper.import 文本> <输出>\n      jasopack pubkey <私钥种子文件>\n      \
         jasopack vectors <目录>\n      jasopack conform <.jaso>"
    );
    ExitCode::from(2)
}

fn flags(f: u32) -> String {
    let mut s = String::new();
    s.push(if f & FLAG_R != 0 { 'r' } else { '-' });
    s.push(if f & FLAG_W != 0 { 'w' } else { '-' });
    s.push(if f & FLAG_X != 0 { 'x' } else { '-' });
    s
}

fn inspect(path: &str) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("读取 {} 失败：{}", path, e);
            return ExitCode::from(2);
        }
    };
    let f = match Jaso::parse(&bytes) {
        Ok(f) => f,
        Err(e) => {
            println!("rejected: {} ({}) {:?}", e.code().name(), e.code().number(), e);
            return ExitCode::from(1);
        }
    };
    let m = &f.manifest;
    let arch = f.arch.map_or("any", Arch::name);
    println!(
        "ok: {} {}.{}.{} kind={:?} arch={} stage={} abi={} host={} lifecycle={:?}",
        m.name, m.version.0, m.version.1, m.version.2, f.kind, arch, f.stage.name(), m.abi, m.host.unwrap_or("-"), m.lifecycle
    );
    println!("file_len={} digest={}", bytes.len(), hex(&f.digest));
    println!("requires={}", m.requires().collect::<Vec<_>>().join(","));
    for d in m.depends() {
        println!("depends {} range={:?}", d.name, d.range.map(|r| r.comparators().to_vec()));
    }
    for img in f.images() {
        let p = img.platform;
        println!(
            "image {} kind={:?} size={:#x} isa={} isa_ext={} target={} float_abi={} abi={}",
            img.index,
            img.kind,
            img.image_size,
            p.isa.map_or("none", Arch::name),
            if p.isa_ext.is_empty() { "-" } else { p.isa_ext },
            p.target.name(),
            p.float_abi.name(),
            p.abi
        );
        for s in img.segments() {
            println!("  segment vaddr={:#x} mem_size={:#x} file_size={:#x} flags={}", s.vaddr, s.mem_size, s.data.len(), flags(s.flags));
        }
        if let Some(c) = img.code() {
            println!("  code format={} payload={}B", c.format, c.payload.len());
        }
        for e in img.exports() {
            println!("  export {} = {:#x}", e.name, e.value);
        }
        println!("  relocs={}", img.relocs().count());
    }
    for e in f.extensions() {
        println!("extension {} v{} critical={} known={} content={}B", e.name, e.version, e.critical, e.is_known(), e.content.len());
    }
    match f.signature() {
        Some(sig) => println!("signature=ed25519 publisher={} key={}", m.publisher.unwrap_or("-"), hex(&sig.publisher_key)),
        None => println!("signature=none publisher={}", m.publisher.unwrap_or("-")),
    }
    ExitCode::SUCCESS
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// 读取 32 字节的私钥种子文件。
fn read_seed(path: &str) -> Result<jaso::build::Signer, ExitCode> {
    match std::fs::read(path) {
        Ok(b) if b.len() == 32 => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&b);
            Ok(jaso::build::Signer::from_seed(&seed))
        }
        Ok(b) => {
            eprintln!("私钥种子文件必须恰好 32 字节（实际 {} 字节）", b.len());
            Err(ExitCode::from(2))
        }
        Err(e) => {
            eprintln!("读取 {} 失败：{}", path, e);
            Err(ExitCode::from(2))
        }
    }
}

fn sign(input: &str, seed: &str, out: &str) -> ExitCode {
    let signer = match read_seed(seed) {
        Ok(s) => s,
        Err(c) => return c,
    };
    let bytes = match std::fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("读取 {} 失败：{}", input, e);
            return ExitCode::from(2);
        }
    };
    match jaso::pack::sign(&bytes, &signer) {
        Ok(signed) => match std::fs::write(out, &signed) {
            Ok(()) => {
                println!("signed: {} key={}", out, hex(&signer.public_key()));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("写入 {} 失败：{}", out, e);
                ExitCode::from(2)
            }
        },
        Err(e) => {
            println!("rejected: {:?}", e);
            ExitCode::from(1)
        }
    }
}

fn pubkey(seed: &str) -> ExitCode {
    match read_seed(seed) {
        Ok(s) => {
            println!("{}", hex(&s.public_key()));
            ExitCode::SUCCESS
        }
        Err(c) => c,
    }
}

fn pack(elf: &str, manifest: &str, arch: &str, stage: &str, out: &str) -> ExitCode {
    let (Some(arch), Some(stage)) = (Arch::from_name(arch), Stage::from_name(stage)) else { return usage() };
    let (elf_bytes, text) = match (std::fs::read(elf), std::fs::read_to_string(manifest)) {
        (Ok(a), Ok(b)) => (a, b),
        _ => {
            eprintln!("读取输入失败");
            return ExitCode::from(2);
        }
    };
    match jaso::pack::from_elf(&elf_bytes, &text, arch, stage) {
        Ok(bytes) => match std::fs::write(out, &bytes) {
            Ok(()) => {
                println!("packed: {} ({} bytes)", out, bytes.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("写入 {} 失败：{}", out, e);
                ExitCode::from(2)
            }
        },
        Err(e) => {
            println!("rejected: {:?}", e);
            ExitCode::from(1)
        }
    }
}

fn migrate(input: &str, out: &str) -> ExitCode {
    let bytes = match std::fs::read(input) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("读取 {} 失败：{}", input, e);
            return ExitCode::from(2);
        }
    };
    match jaso::migrate::from_v0(&bytes) {
        Ok(new) => match std::fs::write(out, &new) {
            Ok(()) => {
                println!("migrated: {} ({} bytes, format 1, unsigned)", out, new.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("写入 {} 失败：{}", out, e);
                ExitCode::from(2)
            }
        },
        Err(e) => {
            println!("rejected: {:?}", e);
            ExitCode::from(1)
        }
    }
}

fn vectors(dir: &str) -> ExitCode {
    let dev = jaso::pack::development_signer();
    let key = dev.public_key();
    let all = jaso::vectors::all(&dev);
    let dir = std::path::Path::new(dir);
    let write = |name: String, bytes: &[u8]| std::fs::write(dir.join(&name), bytes).map_err(|e| format!("写入 {} 失败：{}", name, e));
    let mut bad = 0;
    for v in &all {
        let got = jaso::conformance::expect_line(jaso::conformance::check(&v.bytes, key));
        if got != v.expect {
            eprintln!("{}: 期望 {}，判定为 {}", v.name, v.expect, got);
            bad += 1;
        }
        let r = write(format!("{}.jaso", v.name), &v.bytes).and_then(|()| write(format!("{}.expect", v.name), format!("{}\n", v.expect).as_bytes()));
        if let Err(e) = r {
            eprintln!("{}", e);
            return ExitCode::from(2);
        }
    }
    if let Err(e) = write(jaso::vectors::DEV_KEY_FILE.into(), jaso::vectors::dev_key_text(&key).as_bytes()) {
        eprintln!("{}", e);
        return ExitCode::from(2);
    }
    // 删除不再生成的旧向量（只动 .jaso / .expect）
    let keep = |stem: &str| all.iter().any(|v| v.name == stem);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let ext = p.extension().and_then(|x| x.to_str());
            let stem = p.file_stem().and_then(|x| x.to_str()).unwrap_or("");
            if matches!(ext, Some("jaso" | "expect")) && !keep(stem) {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
    println!("vectors: {} written to {}, {} mismatched", all.len(), dir.display(), bad);
    if bad == 0 { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn conform(p: &str) -> ExitCode {
    match std::fs::read(p) {
        Ok(b) => {
            let key = jaso::pack::development_signer().public_key();
            println!("{}", jaso::conformance::expect_line(jaso::conformance::check(&b, key)));
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("读取 {} 失败：{}", p, e);
            ExitCode::from(2)
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["inspect", p] => inspect(p),
        ["pack", elf, m, arch, stage, out] => pack(elf, m, arch, stage, out),
        ["sign", input, seed, out] => sign(input, seed, out),
        ["hybrid", input, import, out] => hybrid(input, import, out),
        ["pubkey", seed] => pubkey(seed),
        ["migrate", input, out] => migrate(input, out),
        ["vectors", dir] => vectors(dir),
        ["conform", p] => conform(p),
        _ => usage(),
    }
}
