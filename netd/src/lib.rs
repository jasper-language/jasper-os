//! Jasper userspace network service facade.
//!
//! QUIC and TLS are provided by mature libraries. This crate owns only bounded
//! transport profiles and stream/datagram orchestration; it contains no QUIC,
//! TLS or WireGuard cryptography.

use std::sync::Arc;
use std::time::Duration;

pub use quinn;
pub use rustls;

pub mod service;
pub mod jasper_sink;
pub mod wireguard_driver;

/// WireGuard protocol state comes from the same no_std adapter used by the
/// kernel core. Socket, clock and entropy remain service responsibilities.
pub mod wireguard {
    pub use jasper_kernel_core::wireguard::*;
}

/// Bounded transport profile shared by client and server endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicProfile {
    pub max_bidi_streams: u32,
    pub max_uni_streams: u32,
    pub connection_window: u64,
    pub stream_window: u64,
    pub send_window: u64,
    pub datagram_buffer: usize,
    pub idle_timeout: Duration,
}

impl Default for QuicProfile {
    fn default() -> Self {
        Self {
            max_bidi_streams: 64,
            max_uni_streams: 64,
            connection_window: 8 * 1024 * 1024,
            stream_window: 1024 * 1024,
            send_window: 8 * 1024 * 1024,
            datagram_buffer: 64 * 1024,
            idle_timeout: Duration::from_secs(30),
        }
    }
}

impl QuicProfile {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_bidi_streams == 0
            || self.max_uni_streams == 0
            || self.connection_window == 0
            || self.stream_window == 0
            || self.send_window == 0
            || self.datagram_buffer == 0
            || self.idle_timeout.is_zero()
        {
            return Err("all QUIC limits must be non-zero");
        }
        if self.stream_window > self.connection_window {
            return Err("stream window cannot exceed connection window");
        }
        if self.datagram_buffer < 1200 {
            return Err("datagram buffer must admit at least one QUIC datagram");
        }
        Ok(self)
    }

    /// Build the mature library's transport configuration. QUIC TLS 1.3,
    /// Initial/Handshake protection, connection IDs, loss recovery and Cubic
    /// congestion control are supplied by Quinn and rustls.
    pub fn transport_config(self) -> Result<Arc<quinn::TransportConfig>, &'static str> {
        let profile = self.validate()?;
        let mut transport = quinn::TransportConfig::default();
        let connection_window = quinn::VarInt::from_u64(profile.connection_window)
            .map_err(|_| "QUIC window too large")?;
        let stream_window = quinn::VarInt::from_u64(profile.stream_window)
            .map_err(|_| "QUIC stream window too large")?;
        transport
            .max_concurrent_bidi_streams(profile.max_bidi_streams.into())
            .max_concurrent_uni_streams(profile.max_uni_streams.into())
            .receive_window(connection_window)
            .stream_receive_window(stream_window)
            .send_window(profile.send_window)
            .datagram_receive_buffer_size(Some(profile.datagram_buffer))
            .datagram_send_buffer_size(profile.datagram_buffer)
            .max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(profile.idle_timeout)
                    .map_err(|_| "invalid QUIC idle timeout")?,
            ))
            .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
        Ok(Arc::new(transport))
    }
}

/// Install a rustls-based QUIC server config for the supplied certificate.
pub fn server_config(
    certificate: rustls::pki_types::CertificateDer<'static>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
    profile: QuicProfile,
) -> Result<quinn::ServerConfig, &'static str> {
    let mut config = quinn::ServerConfig::with_single_cert(vec![certificate], key)
        .map_err(|_| "invalid QUIC server certificate or key")?;
    config.transport_config(profile.transport_config()?);
    Ok(config)
}

/// Install a rustls-based QUIC client config that trusts exactly the supplied
/// root and offers only TLS 1.3 through Quinn's QUIC crypto provider.
pub fn client_config(
    certificate: rustls::pki_types::CertificateDer<'static>,
    profile: QuicProfile,
) -> Result<quinn::ClientConfig, &'static str> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(certificate)
        .map_err(|_| "invalid QUIC root certificate")?;
    let mut config = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|_| "failed to configure QUIC trust root")?;
    config.transport_config(profile.transport_config()?);
    Ok(config)
}

/// Echo one bidirectional stream and echo one unreliable QUIC datagram.
pub async fn echo_once(
    connection: quinn::Connection,
    max_bytes: usize,
) -> Result<(), &'static str> {
    if max_bytes == 0 {
        return Err("echo bound must be non-zero");
    }
    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|_| "stream accept failed")?;
    let payload = recv
        .read_to_end(max_bytes)
        .await
        .map_err(|_| "stream receive failed or exceeded bound")?;
    send.write_all(&payload)
        .await
        .map_err(|_| "stream echo failed")?;
    send.finish().map_err(|_| "stream finish failed")?;

    let datagram = connection
        .read_datagram()
        .await
        .map_err(|_| "unreliable datagram receive failed")?;
    connection
        .send_datagram(datagram)
        .map_err(|_| "unreliable datagram echo failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use quinn::{Endpoint, ServerConfig};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::sync::oneshot;

    fn endpoint(profile: QuicProfile) -> Endpoint {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let mut server =
            ServerConfig::with_single_cert(vec![certified.cert.der().clone()], key).unwrap();
        server.transport_config(profile.transport_config().unwrap());
        let mut endpoint =
            Endpoint::server(server, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        endpoint.set_default_client_config(
            client_config(certified.cert.der().clone(), profile).unwrap(),
        );
        endpoint
    }

    #[tokio::test]
    async fn quic_tls_streams_datagrams_connection_ids_and_bounded_echo_pass() {
        let profile = QuicProfile {
            max_bidi_streams: 8,
            max_uni_streams: 8,
            connection_window: 128 * 1024,
            stream_window: 32 * 1024,
            send_window: 128 * 1024,
            datagram_buffer: 8 * 1024,
            idle_timeout: Duration::from_secs(5),
        };
        let endpoint = endpoint(profile);
        let server = endpoint.clone();
        let (id_tx, id_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let incoming = server.accept().await.unwrap();
            let connection = incoming.await.unwrap();
            id_tx.send(connection.stable_id()).unwrap();
            echo_once(connection.clone(), 4096).await.unwrap();
            connection.closed().await;
        });
        let connection = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .await
            .unwrap();
        let payload = vec![0x5a; 4096];
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(4096).await.unwrap(), payload);
        connection.send_datagram(vec![1, 2, 3, 4].into()).unwrap();
        assert_eq!(
            connection.read_datagram().await.unwrap().as_ref(),
            &[1, 2, 3, 4]
        );
        assert_ne!(id_rx.await.unwrap(), 0);
        assert_ne!(connection.stable_id(), 0);
        connection.close(0u32.into(), b"done");
        task.await.unwrap();
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn quic_zero_rtt_uses_server_session_ticket_on_reconnect() {
        let endpoint = endpoint(QuicProfile::default());
        let server = endpoint.clone();
        let task = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = server.accept().await.unwrap().accept().unwrap();
                let (connection, established) = incoming
                    .into_0rtt()
                    .unwrap_or_else(|_| panic!("server rejected 0-RTT conversion"));
                let conn = connection.clone();
                tokio::spawn(async move {
                    while let Ok(mut stream) = conn.accept_uni().await {
                        let message = stream.read_to_end(1024).await.unwrap();
                        assert_eq!(message, b"zero-rtt");
                    }
                });
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(b"zero-rtt").await.unwrap();
                stream.finish().unwrap();
                established.await;
            }
        });

        let first = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .into_0rtt()
            .err()
            .expect("first connection cannot have a session ticket")
            .await
            .unwrap();
        let mut stream = first.accept_uni().await.unwrap();
        assert_eq!(stream.read_to_end(1024).await.unwrap(), b"zero-rtt");
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop((stream, first));

        let (second, accepted) = endpoint
            .connect(endpoint.local_addr().unwrap(), "localhost")
            .unwrap()
            .into_0rtt()
            .unwrap_or_else(|_| panic!("session ticket did not enable 0-RTT"));
        let conn = second.clone();
        let writer = tokio::spawn(async move {
            let mut stream = conn.open_uni().await.unwrap();
            stream.write_all(b"zero-rtt").await.unwrap();
            stream.finish().unwrap();
        });
        let mut stream = second.accept_uni().await.unwrap();
        assert_eq!(stream.read_to_end(1024).await.unwrap(), b"zero-rtt");
        assert!(accepted.await);
        writer.await.unwrap();
        task.await.unwrap();
        endpoint.wait_idle().await;
    }

    #[test]
    fn invalid_profiles_fail_before_endpoint_creation() {
        let mut profile = QuicProfile::default();
        profile.datagram_buffer = 0;
        assert!(profile.transport_config().is_err());
        profile = QuicProfile::default();
        profile.stream_window = profile.connection_window + 1;
        assert!(profile.transport_config().is_err());
    }
}
