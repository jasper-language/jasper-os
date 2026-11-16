//! Bounded operator entry point for the LC-2 update service.
//!
//! This executable can inspect a dual-copy control store and recover one
//! prepared/committed transaction from its durable journal. It never accepts an
//! unsigned manifest, never stages new bytes and never bypasses the local install
//! grant required by the library service.

#![forbid(unsafe_code)]

use std::path::Path;

use jasper_lifecycle_staging::control::FileControlStore;
use jasper_lifecycle_staging::UpdateService;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("jasper-update-service: {error}");
        std::process::exit(2);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command, control_root] if command == "status" => {
            let control =
                FileControlStore::open(control_root).map_err(|error| error.to_string())?;
            let current = control.current();
            let candidate = current
                .candidate()
                .map(|(slot, candidate)| {
                    format!(
                        " candidate={slot:?}:{:?}:attempts={}",
                        candidate.state(),
                        candidate.attempts()
                    )
                })
                .unwrap_or_default();
            println!(
                "stage=control active={:?} generation={} transaction={}{}",
                current.active_slot(),
                current.generation(),
                current.transaction_id(),
                candidate
            );
            Ok(())
        }
        [command, control_root, staging_root, digest] if command == "recover" => {
            let digest = parse_digest(digest)?;
            let mut service =
                UpdateService::open(control_root).map_err(|error| error.to_string())?;
            let status = service
                .recover(Path::new(staging_root), digest)
                .map_err(|error| error.to_string())?;
            println!(
                "stage={:?} generation={} manifest={} active={:?} candidate={:?} transaction={}",
                status
                    .stage
                    .ok_or_else(|| "recovery did not publish a stage".to_string())?,
                status.generation,
                encode_digest(status.manifest_sha256.unwrap_or([0; 32])),
                status.active_slot,
                status.candidate_slot,
                status.transaction_id
            );
            Ok(())
        }
        _ => Err("usage: jasper-update-service status <control-root> | \
             recover <control-root> <staging-root> <manifest-sha256-hex>"
            .into()),
    }
}

fn parse_digest(text: &str) -> Result<[u8; 32], String> {
    if text.len() != 64 {
        return Err("manifest digest must contain exactly 64 hex characters".into());
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&text[start..start + 2], 16)
            .map_err(|_| "manifest digest is not hexadecimal")?;
    }
    if digest == [0; 32] {
        return Err("manifest digest cannot be zero".into());
    }
    Ok(digest)
}

fn encode_digest(digest: [u8; 32]) -> String {
    let mut text = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}
