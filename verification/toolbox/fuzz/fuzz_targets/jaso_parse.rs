#![no_main]
//! `.jaso` format 1 结构读取：任意字节不 panic；另以「回填长度与摘要」的副本越过完整性检查，考验结构校验本身。
//! 接受的文件：全部访问器不越界，错误码属于静态类，重写结果仍被接受。
use jaso::{build::Builder, HostPlatform, Jaso, DIGEST_OFFSET, HEADER_SIZE};

fn exercise(b: &[u8]) {
    match Jaso::parse(b) {
        Ok(f) => {
            for img in f.images() {
                let _ = img.segments().map(|s| s.data.len()).sum::<usize>();
                let _ = img.exports().count() + img.relocs().count();
                let _ = img.code().map(|c| c.payload.len());
                let _ = f.select(&HostPlatform { abi: img.platform.abi, ..HostPlatform::jasper_os_native().unwrap() });
            }
            let _ = f.extensions().count() + f.manifest.requires().count() + f.manifest.depends().count();
            let again = Builder::from_file(&f, 0).unwrap().finish().expect("接受的文件重写后必须仍合格");
            assert!(Jaso::parse(&again).is_ok());
        }
        Err(e) => assert!(!e.code().is_load()),
    }
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    exercise(data);
    if data.len() >= HEADER_SIZE {
        let mut b = data.to_vec();
        b[..8].copy_from_slice(&jaso::MAGIC);
        (b[8], b[9]) = (1, 0);
        let n = b.len() as u32;
        b[28..32].copy_from_slice(&n.to_le_bytes());
        let d = jaso::digest_of(&b);
        b[DIGEST_OFFSET..DIGEST_OFFSET + 32].copy_from_slice(&d);
        exercise(&b);
    }
    if let Ok(t) = core::str::from_utf8(data) {
        if let Ok(m) = jaso::Manifest::parse(t) {
            let names: Vec<&str> = m.depends().map(|d| d.name).collect();
            assert!(names.len() <= jaso::manifest::MAX_DEPENDS);
            for (i, n) in names.iter().enumerate() {
                assert!(!n.is_empty() && !names[..i].contains(n));
            }
        }
    }
});
