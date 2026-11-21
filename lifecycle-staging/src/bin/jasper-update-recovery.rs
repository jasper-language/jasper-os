//! Recovery-only maintenance entry point for the LC-2 update service.
//!
//! This executable is not a Jasper native shell command and must not be exposed as
//! the normal `system update status` operation. It exists only in a trusted rescue
//! environment with direct access to protected control/journal paths. It can inspect
//! a dual-copy control store, recover one transaction from its durable journal and
//! archive a terminal transaction. It never accepts an unsigned manifest, stages new
//! bytes or bypasses the local install grant required by the library service.

#![forbid(unsafe_code)]

use std::path::Path;

use jasper_lifecycle_staging::control::FileControlStore;
use jasper_lifecycle_staging::UpdateService;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("jasper-update-recovery: {error}");
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
        [command, control_root, ledger_root] if command == "audit" => {
            let mut service =
                UpdateService::open(control_root).map_err(|error| error.to_string())?;
            service
                .configure_archive_ledger(ledger_root)
                .map_err(|error| error.to_string())?;
            if let Some(receipt) = service
                .last_archive_receipt()
                .map_err(|error| error.to_string())?
            {
                println!(
                    "archive_sequence={} transaction={} manifest={} previous={} terminal={:?}",
                    receipt.archive_sequence(),
                    receipt.transaction_id(),
                    encode_digest(receipt.manifest_sha256()),
                    encode_digest(receipt.previous_sha256()),
                    receipt.terminal_stage()
                );
            } else {
                println!("archive=none");
            }
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
        [command, control_root, staging_root, digest, archive_root] if command == "cleanup" => {
            let digest = parse_digest(digest)?;
            let mut service =
                UpdateService::open(control_root).map_err(|error| error.to_string())?;
            let status = service
                .recover(Path::new(staging_root), digest)
                .map_err(|error| error.to_string())?;
            let stage = status
                .stage
                .ok_or_else(|| "recovery did not publish a stage".to_string())?;
            let archive = service
                .archive_and_cleanup(status.generation, Path::new(archive_root))
                .map_err(|error| error.to_string())?;
            println!(
                "stage={stage:?} generation={} archive={} manifest={} transaction={}",
                status.generation,
                archive.root.display(),
                encode_digest(archive.manifest_sha256),
                archive.record.generation()
            );
            Ok(())
        }
        _ => Err("usage: jasper-update-recovery status <control-root> | \
             audit <control-root> <ledger-root> | \
             recover <control-root> <staging-root> <manifest-sha256-hex> | \
             cleanup <control-root> <staging-root> <manifest-sha256-hex> <archive-root>"
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
