//! Independent Jasper network daemon lifecycle.
//!
//! The daemon owns configuration admission and process lifetime. QUIC transport
//! and TLS remain delegated to Quinn and rustls; this module does not duplicate
//! either protocol.

use std::future::Future;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::service::{QuicEchoService, QuicLimits, QuicServiceStats};
use crate::{server_config, QuicProfile};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonOptions {
    pub bind: SocketAddr,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub limits: QuicLimits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DaemonError {
    Certificate,
    PrivateKey,
    ServerConfig,
    Start,
    Shutdown,
}

impl DaemonError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Certificate => "certificate",
            Self::PrivateKey => "private-key",
            Self::ServerConfig => "server-config",
            Self::Start => "start",
            Self::Shutdown => "shutdown",
        }
    }
}

impl DaemonOptions {
    /// Reject unusable process limits and credential paths before binding.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.limits.validate()?;
        if self.certificate.as_os_str().is_empty() {
            return Err("certificate path must not be empty");
        }
        if self.private_key.as_os_str().is_empty() {
            return Err("private key path must not be empty");
        }
        Ok(())
    }
}

/// Start the daemon and drain it when the supplied shutdown future completes.
///
/// Credential loading, transport admission and serving all happen in this
/// function so process startup has one failure-atomic path.
pub async fn run_until<F>(
    options: DaemonOptions,
    profile: QuicProfile,
    shutdown: F,
) -> Result<QuicServiceStats, DaemonError>
where
    F: Future<Output = ()>,
{
    options.validate().map_err(|_| DaemonError::ServerConfig)?;
    let certificate = load_certificate(&options.certificate)?;
    let private_key = load_private_key(&options.private_key)?;
    let config =
        server_config(certificate, private_key, profile).map_err(|_| DaemonError::ServerConfig)?;
    let service = QuicEchoService::start(config, options.bind, options.limits)
        .map_err(|_| DaemonError::Start)?;
    shutdown.await;
    service.shutdown().await.map_err(|_| DaemonError::Shutdown)
}

fn load_certificate(path: &Path) -> Result<CertificateDer<'static>, DaemonError> {
    CertificateDer::from_pem_file(path).map_err(|_| DaemonError::Certificate)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, DaemonError> {
    PrivateKeyDer::from_pem_file(path).map_err(|_| DaemonError::PrivateKey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn options() -> DaemonOptions {
        DaemonOptions {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            certificate: "server-cert.pem".into(),
            private_key: "server-key.pem".into(),
            limits: QuicLimits {
                max_connections: 2,
                max_stream_bytes: 4096,
                max_datagram_bytes: 1200,
            },
        }
    }

    #[test]
    fn configuration_requires_nonzero_limits_and_credentials() {
        assert_eq!(options().validate(), Ok(()));

        let mut invalid = options();
        invalid.limits.max_connections = 0;
        assert!(invalid.validate().is_err());

        let mut invalid = options();
        invalid.certificate.clear();
        assert!(invalid.validate().is_err());

        let mut invalid = options();
        invalid.private_key.clear();
        assert!(invalid.validate().is_err());
    }

    #[tokio::test]
    async fn startup_failure_is_reported_before_bind() {
        let mut missing = options();
        missing.certificate = PathBuf::from("/definitely/missing/jasper-netd-cert.pem");
        let result = run_until(missing, QuicProfile::default(), std::future::ready(())).await;
        assert_eq!(result, Err(DaemonError::Certificate));
    }
}
