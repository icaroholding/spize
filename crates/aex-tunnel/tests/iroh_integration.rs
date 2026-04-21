//! 2-peer integration test for [`IrohTunnel`].
//!
//! Decision 3A of the Sprint 2 plan-eng-review (2026-04-21): the Iroh
//! transport ships with a live 2-peer test marked `#[ignore]`, so it
//! runs on demand but doesn't block default CI (which has no relay
//! reachability).
//!
//! Scenario:
//!
//! 1. Peer A binds a local TCP echo server on 127.0.0.1.
//! 2. Peer A wraps it in an `IrohTunnel`; the tunnel brings up an iroh
//!    endpoint, contacts a DERP relay, and exposes
//!    `iroh:<EndpointId>@<relay>` as its public URL.
//! 3. Peer B builds a bare iroh `Endpoint`, dials A by its
//!    `EndpointAddr`, opens a bi-directional stream, writes bytes, and
//!    reads them back through A's QUIC→TCP proxy.
//! 4. The test asserts the echoed bytes match, proving the full
//!    accept/forward/bridge pipeline.
//!
//! Requires outbound network access to iroh's default DERP servers.
//! Run with: `cargo test -p aex-tunnel --test iroh_integration -- --ignored`

use std::time::Duration;

use aex_tunnel::{IrohTunnel, TunnelProvider, TunnelStatus, IROH_ALPN};
use iroh::{Endpoint as IrohEndpoint, SecretKey};
use tokio::net::TcpListener;
use tokio::time::timeout;

const CONNECT_BUDGET: Duration = Duration::from_secs(45);

#[tokio::test]
#[ignore]
async fn two_peers_echo_over_iroh() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aex_tunnel=debug".into()),
        )
        .with_test_writer()
        .try_init();

    // Peer A: local TCP echo server the IrohTunnel will proxy traffic to.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("tcp bind");
    let local_port = listener.local_addr().unwrap().port();
    let _echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut r, mut w) = sock.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });

    // Peer A: IrohTunnel with a pinned SecretKey so we can inspect the
    // resulting EndpointId deterministically. The key bytes are
    // hard-coded — this is a test, not a real identity.
    let secret_a = SecretKey::from_bytes(&[42u8; 32]);
    let expected_node_id = secret_a.public();

    let mut tunnel_a = IrohTunnel::new().with_secret_key(secret_a);
    timeout(CONNECT_BUDGET, tunnel_a.start(local_port))
        .await
        .expect("outer timeout starting IrohTunnel")
        .expect("IrohTunnel.start");

    let public_url = tunnel_a.public_url().expect("public_url after start");
    assert!(
        public_url.starts_with("iroh:"),
        "expected iroh: URL, got {public_url}"
    );
    assert!(
        public_url.contains(&expected_node_id.to_string()),
        "URL should contain EndpointId, got {public_url}"
    );
    assert!(matches!(tunnel_a.status(), TunnelStatus::Connected { .. }));

    // Grab the full addressing info to hand to peer B. Production code
    // would parse the URL and resolve via DNS; the test takes the short
    // path via the test-only escape hatch.
    let a_addr = tunnel_a
        .iroh_endpoint()
        .expect("iroh endpoint present after start")
        .addr();

    // Peer B: plain iroh endpoint, no tunnel, just a client.
    let endpoint_b = IrohEndpoint::builder()
        .alpns(vec![IROH_ALPN.to_vec()])
        .bind()
        .await
        .expect("peer B iroh bind");
    timeout(CONNECT_BUDGET, endpoint_b.online())
        .await
        .expect("peer B online timeout");

    let conn = timeout(CONNECT_BUDGET, endpoint_b.connect(a_addr, IROH_ALPN))
        .await
        .expect("outer timeout during connect")
        .expect("peer B connect to peer A");

    let (mut send, mut recv) = conn.open_bi().await.expect("peer B open_bi against peer A");

    let payload = b"hello-aex-iroh\n";
    send.write_all(payload).await.expect("write payload");
    send.finish().expect("finish send side");

    let read_result = timeout(Duration::from_secs(10), recv.read_to_end(1024)).await;
    let read_result = read_result.expect("outer timeout reading echo");
    let echoed = read_result.expect("read_to_end");

    assert_eq!(
        &echoed[..],
        &payload[..],
        "TCP echo server should round-trip the payload over Iroh"
    );

    // Clean shutdown on both sides.
    drop(conn);
    endpoint_b.close().await;
    tunnel_a.stop().await.expect("tunnel_a stop");
    assert!(tunnel_a.public_url().is_none());
    assert!(matches!(
        tunnel_a.status(),
        TunnelStatus::Disconnected { .. }
    ));
}
