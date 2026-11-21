//! Standalone Jasper network daemon.
//!
//! Configuration is explicit rather than inherited from Linux or Android
//! process conventions. The daemon terminates cleanly on SIGINT/SIGTERM and
//! reports the final transport state.

use std::path::PathBuf;
use std::process::ExitCode;

use jasper_netd::daemon::{self, DaemonOptions};
use jasper_netd::service::QuicLimits;
use jasper_netd::QuicProfile;

const USAGE: &str = "\
usage: jasper-netd --bind ADDRESS --certificate PEM --private-key PEM \
--max-connections N --max-stream-bytes N --max-datagram-bytes N [--check]

All limits are required process-profile inputs. Zero limits are rejected.";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("jasper-netd: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    let (options, check_only) = parse_args(&args)?;
    options.validate().map_err(str::to_owned)?;
    if check_only {
        options
            .validate_credentials(QuicProfile::default())
            .map_err(|error| format!("{} failed", error.name()))?;
        println!(
            "jasper-netd state=configuration-valid bind={} max_connections={} max_stream_bytes={} max_datagram_bytes={}",
            options.bind,
            options.limits.max_connections,
            options.limits.max_stream_bytes,
            options.limits.max_datagram_bytes
        );
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| "failed to create async runtime".to_owned())?;
    runtime.block_on(async {
        let service = daemon::start(options, QuicProfile::default())
            .map_err(|error| format!("{} failed", error.name()))?;
        println!(
            "jasper-netd state={:?} bind={}",
            service.state(),
            service.local_addr()
        );
        let shutdown = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                match (
                    signal(SignalKind::interrupt()),
                    signal(SignalKind::terminate()),
                ) {
                    (Ok(mut interrupt), Ok(mut terminate)) => {
                        tokio::select! {
                            _ = interrupt.recv() => {}
                            _ = terminate.recv() => {}
                        }
                    }
                    _ => {
                        let _ = tokio::signal::ctrl_c().await;
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
            }
        };
        shutdown.await;
        let stats = service
            .shutdown()
            .await
            .map_err(|error| format!("{} failed", error.name()))?;
        println!(
            "jasper-netd state=stopped accepted={} rejected={} active={} completed={} streams={} errors={}",
            stats.accepted_connections,
            stats.rejected_connections,
            stats.active_connections,
            stats.completed_connections,
            stats.streams,
            stats.errors
        );
        Ok(())
    })
}

fn parse_args(args: &[String]) -> Result<(DaemonOptions, bool), String> {
    let mut bind = None;
    let mut certificate = None;
    let mut private_key = None;
    let mut max_connections = None;
    let mut max_stream_bytes = None;
    let mut max_datagram_bytes = None;
    let mut check_only = false;
    let mut index = 0;

    while index < args.len() {
        let flag = &args[index];
        if flag == "--check" {
            if check_only {
                return Err("duplicate --check".into());
            }
            check_only = true;
            index += 1;
            continue;
        }
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--bind" => set_once(&mut bind, value.parse().map_err(|_| "--bind is invalid")?)?,
            "--certificate" => set_once(&mut certificate, PathBuf::from(value))?,
            "--private-key" => set_once(&mut private_key, PathBuf::from(value))?,
            "--max-connections" => {
                set_once(&mut max_connections, parse_nonzero(value, flag)?)?;
            }
            "--max-stream-bytes" => {
                set_once(&mut max_stream_bytes, parse_nonzero(value, flag)?)?;
            }
            "--max-datagram-bytes" => {
                set_once(&mut max_datagram_bytes, parse_nonzero(value, flag)?)?;
            }
            _ => return Err(format!("unknown argument {flag}")),
        }
        index += 2;
    }

    Ok((
        DaemonOptions {
            bind: bind.ok_or("missing --bind")?,
            certificate: certificate.ok_or("missing --certificate")?,
            private_key: private_key.ok_or("missing --private-key")?,
            limits: QuicLimits {
                max_connections: max_connections.ok_or("missing --max-connections")?,
                max_stream_bytes: usize::try_from(
                    max_stream_bytes.ok_or("missing --max-stream-bytes")?,
                )
                .map_err(|_| "--max-stream-bytes is too large")?,
                max_datagram_bytes: usize::try_from(
                    max_datagram_bytes.ok_or("missing --max-datagram-bytes")?,
                )
                .map_err(|_| "--max-datagram-bytes is too large")?,
            },
        },
        check_only,
    ))
}

fn parse_nonzero(value: &str, flag: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{flag} must be a non-zero integer"))?;
    if parsed == 0 {
        return Err(format!("{flag} must be a non-zero integer"));
    }
    Ok(parsed)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err("duplicate argument".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_args() -> Vec<String> {
        [
            "--bind",
            "127.0.0.1:4433",
            "--certificate",
            "cert.pem",
            "--private-key",
            "key.pem",
            "--max-connections",
            "2",
            "--max-stream-bytes",
            "4096",
            "--max-datagram-bytes",
            "1200",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn cli_requires_every_admitted_limit() {
        let (options, check) = parse_args(&valid_args()).unwrap();
        assert!(!check);
        assert_eq!(options.limits.max_connections, 2);

        let mut missing = valid_args();
        missing.truncate(missing.len() - 2);
        assert!(parse_args(&missing).is_err());

        let mut zero = valid_args();
        zero[9] = "0".into();
        assert!(parse_args(&zero).is_err());
    }

    #[test]
    fn cli_rejects_duplicate_and_unknown_arguments() {
        let mut duplicate = valid_args();
        duplicate.extend(["--bind".into(), "127.0.0.1:4434".into()]);
        assert!(parse_args(&duplicate).is_err());

        let mut unknown = valid_args();
        unknown.extend(["--compat-daemon".into(), "yes".into()]);
        assert!(parse_args(&unknown).is_err());
    }
}
