//! Integration test for `CloudflareQuickTunnel` lifecycle.
//!
//! Skipped by default (`#[ignore]`) because it requires:
//! - `cloudflared` binary in PATH
//! - Outbound network access to Cloudflare
//!
//! Run with: `cargo test -p aex-tunnel --test cloudflared_integration -- --ignored`

use std::time::Duration;

use aex_tunnel::{CloudflareQuickTunnel, TunnelProvider, TunnelStatus};
use tokio::net::TcpListener;

#[tokio::test]
#[ignore]
async fn cloudflared_start_emits_url_and_drop_cleans_up() {
    // Tiny TCP acceptor so cloudflared has a local endpoint to tunnel to.
    // cloudflared doesn't require the target to speak HTTP to start; it just
    // needs the port to exist.
    let acceptor = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = acceptor.local_addr().unwrap().port();
    let _accept_task = tokio::spawn(async move {
        loop {
            if acceptor.accept().await.is_err() {
                break;
            }
        }
    });

    let mut tunnel = CloudflareQuickTunnel::new();

    // Give cloudflared up to 45s to boot and publish a URL. The provider
    // already has a 30s internal timeout — this is a generous outer bound.
    let start_result = tokio::time::timeout(Duration::from_secs(45), tunnel.start(port)).await;
    let start_result = start_result.expect("outer timeout waiting for tunnel.start");
    start_result.expect("tunnel.start returned an error");

    let url = tunnel.public_url().expect("public URL should be set");
    assert!(
        url.starts_with("https://"),
        "tunnel URL should be https, got {url}"
    );
    assert!(
        url.contains("trycloudflare.com"),
        "tunnel URL should be a trycloudflare quick tunnel, got {url}"
    );

    assert!(matches!(tunnel.status(), TunnelStatus::Connected { .. }));
    assert!(tunnel.is_alive(), "tunnel child process should be alive");

    tunnel.stop().await.expect("tunnel.stop returned an error");

    assert!(
        !tunnel.is_alive(),
        "tunnel child should be dead after stop()"
    );
    assert!(tunnel.public_url().is_none());
    assert!(matches!(tunnel.status(), TunnelStatus::Disconnected { .. }));
}

#[tokio::test]
#[ignore]
async fn cloudflared_drop_kills_child() {
    // Verify the kill_on_drop guard: if the caller forgets to stop(), the
    // Drop impl should still kill the child so we don't leak cloudflared
    // processes after a panic.
    let acceptor = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = acceptor.local_addr().unwrap().port();
    let _accept_task = tokio::spawn(async move {
        loop {
            if acceptor.accept().await.is_err() {
                break;
            }
        }
    });

    {
        let mut tunnel = CloudflareQuickTunnel::new();
        tokio::time::timeout(Duration::from_secs(45), tunnel.start(port))
            .await
            .expect("outer timeout")
            .expect("tunnel.start");
        assert!(tunnel.public_url().is_some());
        // Tunnel dropped here without an explicit stop().
    }

    // Give the OS a moment to reap the child.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // We can't directly observe child-process state from here, but we can
    // at least observe that a fresh tunnel on the same port starts cleanly
    // (which would fail if we leaked a prior cloudflared holding onto the
    // control channel).
    let mut fresh = CloudflareQuickTunnel::new();
    tokio::time::timeout(Duration::from_secs(45), fresh.start(port))
        .await
        .expect("outer timeout (fresh)")
        .expect("fresh tunnel.start");
    assert!(fresh.public_url().is_some());
    fresh.stop().await.unwrap();
}
