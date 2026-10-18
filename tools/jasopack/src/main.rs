//! jasopack：宿主侧 `.jaso` 工具。
//! Host-side `.jaso` tool.
//!
//! ```text
//! jasopack pack <ELF> <清单文件> <指令集> <装载阶段> <输出>   打包（指令集：x86_64|aarch64|riscv64|riscv32；阶段：runtime|boot|build）
//! jasopack inspect <.jaso>                                   校验并列出头部、清单、段、导出、重定位数与签名
//! jasopack sign <.jaso> <私钥种子文件> <输出>                  以发布者私钥（32 字节种子文件）签名（替换已有签名）
//! jasopack pubkey <私钥种子文件>                              输出该私钥对应的公钥（十六进制，写进受信发布者表）
//! ```
//! 退出码：0 成功；1 输入不合法（校验或打包失败）；2 用法错误或读写失败。

use std::process::ExitCode;

use jaso::{Arch, Image, Stage, FLAG_R, FLAG_W, FLAG_X};

fn usage() -> ExitCode {
    eprintln!(
        "用法：jasopack pack <ELF> <清单文件> <指令集> <装载阶段> <输出>\n      jasopack inspect <.jaso>\n      \
         jasopack sign <.jaso> <私钥种子文件> <输出>\n      jasopack pubkey <私钥种子文件>"
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
    let img = match Image::parse(&bytes) {
        Ok(i) => i,
        Err(e) => {
            println!("rejected: {:?}", e);
            return ExitCode::from(1);
        }
    };
    let m = &img.manifest;
    println!("ok: {} {}.{}.{} arch={} stage={} abi={} host={}", m.name, m.version.0, m.version.1, m.version.2, img.arch.name(), img.stage.name(), m.abi, m.host.unwrap_or("-"));
    println!("image_size={} file_len={} digest={}", img.image_size, bytes.len(), img.digest.iter().map(|b| format!("{:02x}", b)).collect::<String>());
    println!("requires={}", m.requires().collect::<Vec<_>>().join(","));
    for s in img.segments() {
        println!("segment vaddr={:#x} mem_size={:#x} file_size={:#x} flags={}", s.vaddr, s.mem_size, s.data.len(), flags(s.flags));
    }
    for e in img.exports() {
        println!("export {} = {:#x}", e.name, e.value);
    }
    println!("relocs={}", img.relocs().count());
    match img.signature() {
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["inspect", p] => inspect(p),
        ["pack", elf, m, arch, stage, out] => pack(elf, m, arch, stage, out),
        ["sign", input, seed, out] => sign(input, seed, out),
        ["pubkey", seed] => pubkey(seed),
        _ => usage(),
    }
}
