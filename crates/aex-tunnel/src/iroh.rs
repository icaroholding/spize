//! Iroh peer-to-peer tunnel provider.
//!
//! Per ADR-0002 Iroh is a first-class AEX transport. Per ADR-0015 it's
//! pinned to `=0.96.0` and every `iroh::*` type stays behind this
//! [`TunnelProvider`] impl so nothing else in the protocol depends on
//! Iroh's API surface.
//!
//! The "public URL" returned by [`IrohTunnel::public_url`] is not an
//! HTTP URL — it's the AEX-specific identifier
//! `iroh:<EndpointId>[@<relay_url>]` that recipient SDKs recognise and
//! dial via Iroh. See `crates/aex-core/src/endpoint.rs` for the wire
//! format.
//!
//! While the tunnel is running, incoming QUIC connections on
//! [`IROH_ALPN`] are proxied 1:1 to `127.0.0.1:<local_port>`. Each
//! bi-directional QUIC stream maps to one TCP connection against the
//! local HTTP server. Per ADR-0019, bind failures bubble up as
//! `TunnelError::Other` so the orchestrator can degrade gracefully.
//!
//! ADR-0011 says the Iroh `EndpointId` must eventually be derived from
//! the same Ed25519 keypair as the `spize:*` identity. That wiring
//! lands alongside key rotation (PR E1); for now [`IrohTunnel`] accepts
//! an optional [`SecretKey`] via [`IrohTunnel::with_secret_key`] so
//! tests can pin the NodeId.

use std::time::Duration;

use async_trait::async_trait;
use iroh::{Endpoint as IrohEndpoint, SecretKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use crate::{
    provider::{TunnelProvider, TunnelStatus},
    TunnelError, TunnelResult,
};

/// ALPN used for AEX data-plane streams over Iroh.
///
/// Peers on both ends declare this so Iroh's TLS handshake rejects
/// non-AEX clients before any application bytes flow.
pub const IROH_ALPN: &[u8] = b"aex/v1";

const DEFAULT_ONLINE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct IrohTunnel {
    endpoint: Option<IrohEndpoint>,
    public_url: Option<String>,
    status: TunnelStatus,
    alpn: Vec<u8>,
    online_timeout: Duration,
    secret_key: Option<SecretKey>,
    accept_task: Option<JoinHandle<()>>,
}

impl Default for IrohTunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl IrohTunnel {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            public_url: None,
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            alpn: IROH_ALPN.to_vec(),
            online_timeout: DEFAULT_ONLINE_TIMEOUT,
            secret_key: None,
            accept_task: None,
        }
    }

    /// Shorter online-wait, useful in integration tests so a missing
    /// relay doesn't stall CI for 30s.
    pub fn with_online_timeout(mut self, timeout: Duration) -> Self {
        self.online_timeout = timeout;
        self
    }

    /// Override the ALPN. Tests use this to isolate parallel runs; the
    /// AEX data plane always uses [`IROH_ALPN`].
    pub fn with_alpn(mut self, alpn: impl Into<Vec<u8>>) -> Self {
        self.alpn = alpn.into();
        self
    }

    /// Pin the Ed25519 identity used as the Iroh `EndpointId`. Without
    /// this, each `start()` generates a fresh random identity.
    /// ADR-0011 will eventually derive this from the same keypair that
    /// backs the `spize:*` identity.
    pub fn with_secret_key(mut self, secret_key: SecretKey) -> Self {
        self.secret_key = Some(secret_key);
        self
    }

    /// Returns the underlying Iroh endpoint while the tunnel is
    /// running. Test-only escape hatch so a second tunnel can dial
    /// without reconstructing the `EndpointAddr`; production code
    /// should go through the URL.
    #[doc(hidden)]
    pub fn iroh_endpoint(&self) -> Option<&IrohEndpoint> {
        self.endpoint.as_ref()
    }
}

#[async_trait]
impl TunnelProvider for IrohTunnel {
    async fn start(&mut self, local_port: u16) -> TunnelResult<()> {
        if self.endpoint.is_some() {
            return Err(TunnelError::AlreadyRunning);
        }

        self.status = TunnelStatus::Connecting;

        let mut builder = IrohEndpoint::builder().alpns(vec![self.alpn.clone()]);
        if let Some(sk) = self.secret_key.clone() {
            builder = builder.secret_key(sk);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| TunnelError::Other(format!("iroh bind failed: {e}")))?;

        // Wait until the endpoint has contacted its home relay. Without
        // this the returned URL has no relay component and remote peers
        // can't reach us through NAT.
        if timeout(self.online_timeout, endpoint.online())
            .await
            .is_err()
        {
            endpoint.close().await;
            self.status = TunnelStatus::Disconnected {
                reason: format!(
                    "timeout after {}s waiting for iroh relay",
                    self.online_timeout.as_secs()
                ),
            };
            return Err(TunnelError::UrlTimeout {
                secs: self.online_timeout.as_secs(),
            });
        }

        let addr = endpoint.addr();
        let endpoint_id = endpoint.id();
        let relay_segment = addr
            .relay_urls()
            .next()
            .map(|u| format!("@{u}"))
            .unwrap_or_default();
        let url = format!("iroh:{endpoint_id}{relay_segment}");

        let accept_ep = endpoint.clone();
        let accept_task = tokio::spawn(run_accept_loop(accept_ep, local_port));

        self.accept_task = Some(accept_task);
        self.public_url = Some(url.clone());
        self.status = TunnelStatus::Connected { url };
        self.endpoint = Some(endpoint);
        Ok(())
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close().await;
        }
        self.public_url = None;
        self.status = TunnelStatus::Disconnected {
            reason: "stopped".into(),
        };
        Ok(())
    }

    fn public_url(&self) -> Option<String> {
        self.public_url.clone()
    }

    fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}

async fn run_accept_loop(endpoint: IrohEndpoint, local_port: u16) {
    loop {
        let Some(incoming) = endpoint.accept().await else {
            tracing::debug!(target: "aex_tunnel::iroh", "accept loop: endpoint closed");
            return;
        };
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(target: "aex_tunnel::iroh", "incoming connection error: {e}");
                continue;
            }
        };
        let peer = conn.remote_id();
        tracing::debug!(target: "aex_tunnel::iroh", peer = %peer, "iroh connection accepted");
        tokio::spawn(run_connection_streams(conn, local_port));
    }
}

async fn run_connection_streams(conn: iroh::endpoint::Connection, local_port: u16) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!(target: "aex_tunnel::iroh", "conn stream loop ended: {e}");
                return;
            }
        };
        tokio::spawn(proxy_stream_to_tcp(send, recv, local_port));
    }
}

async fn proxy_stream_to_tcp(
    mut remote_send: impl AsyncWrite + Unpin + Send + 'static,
    mut remote_recv: impl AsyncRead + Unpin + Send + 'static,
    local_port: u16,
) {
    let tcp = match TcpStream::connect(("127.0.0.1", local_port)).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "aex_tunnel::iroh", "local TCP connect failed: {e}");
            return;
        }
    };
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let up = tokio::io::copy(&mut remote_recv, &mut tcp_write);
    let down = tokio::io::copy(&mut tcp_read, &mut remote_send);
    let _ = tokio::join!(up, down);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_overrides_are_applied() {
        let t = IrohTunnel::new()
            .with_online_timeout(Duration::from_secs(3))
            .with_alpn(b"aex/test".to_vec());
        assert_eq!(t.online_timeout, Duration::from_secs(3));
        assert_eq!(t.alpn, b"aex/test".to_vec());
    }

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let mut t = IrohTunnel::new();
        t.stop().await.unwrap();
        assert!(matches!(t.status(), TunnelStatus::Disconnected { .. }));
        assert!(t.public_url().is_none());
    }

    // The `AlreadyRunning` branch requires a real bound endpoint, which
    // needs network + a relay; it's exercised by the ignored 2-peer
    // integration test at tests/iroh_integration.rs.
}
