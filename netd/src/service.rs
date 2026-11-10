//! Runnable hosted QUIC echo service lifecycle.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuicLimits {
    pub max_connections: u64,
    pub max_stream_bytes: usize,
    pub max_datagram_bytes: usize,
}

impl Default for QuicLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_stream_bytes: 1024 * 1024,
            max_datagram_bytes: 1200,
        }
    }
}

impl QuicLimits {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.max_connections == 0 {
            return Err("max connections must be non-zero");
        }
        if self.max_stream_bytes == 0 {
            return Err("max stream bytes must be non-zero");
        }
        if !(1..=65535).contains(&self.max_datagram_bytes) {
            return Err("max datagram bytes must fit QUIC DATAGRAM");
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
}

impl ServiceState {
    fn encode(self) -> u8 {
        match self {
            Self::Starting => 0,
            Self::Running => 1,
            Self::Stopping => 2,
            Self::Stopped => 3,
            Self::Failed => 4,
        }
    }

    fn decode(value: u8) -> Self {
        match value {
            0 => Self::Starting,
            1 => Self::Running,
            2 => Self::Stopping,
            3 => Self::Stopped,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct QuicServiceStats {
    pub accepted_connections: u64,
    pub rejected_connections: u64,
    pub active_connections: u64,
    pub completed_connections: u64,
    pub streams: u64,
    pub stream_bytes: u64,
    pub datagrams_received: u64,
    pub datagrams_sent: u64,
    pub errors: u64,
}

#[derive(Default)]
struct Metrics {
    accepted: AtomicU64,
    rejected: AtomicU64,
    active: AtomicU64,
    completed: AtomicU64,
    streams: AtomicU64,
    stream_bytes: AtomicU64,
    datagrams_received: AtomicU64,
    datagrams_sent: AtomicU64,
    errors: AtomicU64,
}

impl Metrics {
    fn snapshot(&self) -> QuicServiceStats {
        QuicServiceStats {
            accepted_connections: self.accepted.load(Ordering::Relaxed),
            rejected_connections: self.rejected.load(Ordering::Relaxed),
            active_connections: self.active.load(Ordering::Relaxed),
            completed_connections: self.completed.load(Ordering::Relaxed),
            streams: self.streams.load(Ordering::Relaxed),
            stream_bytes: self.stream_bytes.load(Ordering::Relaxed),
            datagrams_received: self.datagrams_received.load(Ordering::Relaxed),
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

pub struct QuicEchoService {
    endpoint: quinn::Endpoint,
    metrics: Arc<Metrics>,
    state: Arc<AtomicU8>,
    stop: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
    local_addr: SocketAddr,
}

impl QuicEchoService {
    pub fn start(
        server_config: quinn::ServerConfig,
        bind: SocketAddr,
        limits: QuicLimits,
    ) -> Result<Self, &'static str> {
        let limits = limits.validate()?;
        let endpoint = quinn::Endpoint::server(server_config, bind)
            .map_err(|_| "failed to bind QUIC endpoint")?;
        let local_addr = endpoint
            .local_addr()
            .map_err(|_| "failed to read QUIC endpoint address")?;
        let metrics = Arc::new(Metrics::default());
        let state = Arc::new(AtomicU8::new(ServiceState::Starting.encode()));
        let stop = Arc::new(Notify::new());
        let task_endpoint = endpoint.clone();
        let task_metrics = metrics.clone();
        let task_state = state.clone();
        let task_stop = stop.clone();
        let task = tokio::spawn(async move {
            task_state.store(ServiceState::Running.encode(), Ordering::Release);
            loop {
                tokio::select! {
                    _ = task_stop.notified() => break,
                    incoming = task_endpoint.accept() => {
                        let Some(incoming) = incoming else { break };
                        let active = task_metrics.active.load(Ordering::Acquire);
                        if active >= limits.max_connections {
                            task_metrics.rejected.fetch_add(1, Ordering::Relaxed);
                            incoming.refuse();
                            continue;
                        }
                        task_metrics.accepted.fetch_add(1, Ordering::Relaxed);
                        task_metrics.active.fetch_add(1, Ordering::Relaxed);
                        let metrics = task_metrics.clone();
                        let limits = limits;
                        tokio::spawn(async move {
                            match incoming.await {
                                Ok(connection) => {
                                    if serve_connection(connection.clone(), limits, metrics.clone())
                                        .await
                                        .is_err()
                                    {
                                        metrics.errors.fetch_add(1, Ordering::Relaxed);
                                    }
                                    let _ = connection.close(0u32.into(), b"connection complete");
                                }
                                Err(_) => {
                                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            metrics.active.fetch_sub(1, Ordering::Release);
                            metrics.completed.fetch_add(1, Ordering::Relaxed);
                        });
                    }
                }
            }
            task_endpoint.close(0u32.into(), b"service stopping");
            task_state.store(ServiceState::Stopped.encode(), Ordering::Release);
        });
        Ok(Self {
            endpoint,
            metrics,
            state,
            stop,
            task,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn state(&self) -> ServiceState {
        ServiceState::decode(self.state.load(Ordering::Acquire))
    }

    pub fn stats(&self) -> QuicServiceStats {
        self.metrics.snapshot()
    }

    pub async fn shutdown(mut self) -> Result<QuicServiceStats, &'static str> {
        if self.state() != ServiceState::Stopping {
            self.state
                .store(ServiceState::Stopping.encode(), Ordering::Release);
            self.stop.notify_one();
            self.endpoint.close(0u32.into(), b"service stopping");
        }
        if tokio::time::timeout(std::time::Duration::from_secs(5), &mut self.task)
            .await
            .is_err()
        {
            self.state
                .store(ServiceState::Failed.encode(), Ordering::Release);
            return Err("QUIC service shutdown timed out");
        }
        if tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while self.metrics.active.load(Ordering::Acquire) != 0 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .is_err()
        {
            self.state
                .store(ServiceState::Failed.encode(), Ordering::Release);
            return Err("QUIC connection drain timed out");
        }
        Ok(self.stats())
    }
}

async fn serve_connection(
    connection: quinn::Connection,
    limits: QuicLimits,
    metrics: Arc<Metrics>,
) -> Result<(), &'static str> {
    loop {
        tokio::select! {
            incoming = connection.accept_bi() => {
                let Ok((mut send, mut recv)) = incoming else { break };
                metrics.streams.fetch_add(1, Ordering::Relaxed);
                let stream_metrics = metrics.clone();
                tokio::spawn(async move {
                    match recv.read_to_end(limits.max_stream_bytes).await {
                        Ok(bytes) => {
                            stream_metrics.stream_bytes.fetch_add(bytes.len() as u64, Ordering::Relaxed);
                            if send.write_all(&bytes).await.is_err() {
                                stream_metrics.errors.fetch_add(1, Ordering::Relaxed);
                            }
                            let _ = send.finish();
                        }
                        Err(_) => {
                            stream_metrics.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
            datagram = connection.read_datagram() => {
                let Ok(datagram) = datagram else { break };
                if datagram.len() > limits.max_datagram_bytes {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                metrics.datagrams_received.fetch_add(1, Ordering::Relaxed);
                if connection.send_datagram(datagram).is_ok() {
                    metrics.datagrams_sent.fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics.errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ = connection.closed() => break,
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr};

    use quinn::Endpoint;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use crate::{client_config, server_config, QuicProfile};

    fn endpoint_configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certified.signing_key.serialize_der(),
        ));
        let profile = QuicProfile::default();
        (
            server_config(certificate.clone(), key, profile).unwrap(),
            client_config(certificate, profile).unwrap(),
        )
    }

    #[tokio::test]
    async fn hosted_service_stream_datagram_stats_and_shutdown_return_to_zero() {
        let (server, client) = endpoint_configs();
        let service = QuicEchoService::start(
            server,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            QuicLimits {
                max_connections: 2,
                max_stream_bytes: 4096,
                max_datagram_bytes: 1200,
            },
        )
        .unwrap();
        let mut client_endpoint =
            Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(client);
        let connection = client_endpoint
            .connect(service.local_addr(), "localhost")
            .unwrap()
            .await
            .unwrap();

        let payload = vec![0x42; 1024];
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(4096).await.unwrap(), payload);
        connection.send_datagram(vec![7, 8, 9].into()).unwrap();
        assert_eq!(
            connection.read_datagram().await.unwrap().as_ref(),
            &[7, 8, 9]
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let running = service.stats();
        assert_eq!(running.accepted_connections, 1);
        assert_eq!(running.active_connections, 1);
        assert_eq!(running.streams, 1);
        assert_eq!(running.datagrams_received, 1);
        assert_eq!(running.datagrams_sent, 1);

        connection.close(0u32.into(), b"test done");
        client_endpoint.wait_idle().await;
        let stats = service.shutdown().await.unwrap();
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.completed_connections, 1);
        assert_eq!(stats.errors, 0);
    }

    #[test]
    fn zero_limits_are_rejected_before_endpoint_creation() {
        assert!(QuicLimits {
            max_connections: 0,
            ..QuicLimits::default()
        }
        .validate()
        .is_err());
        assert!(QuicLimits {
            max_stream_bytes: 0,
            ..QuicLimits::default()
        }
        .validate()
        .is_err());
        assert!(QuicLimits {
            max_datagram_bytes: 0,
            ..QuicLimits::default()
        }
        .validate()
        .is_err());
    }
}
