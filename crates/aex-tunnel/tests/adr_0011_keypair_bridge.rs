//! ADR-0011 invariant: the same Ed25519 keypair that backs a
//! `spize:org/name:fingerprint` identity is used as the Iroh
//! `EndpointId` (NodeID).
//!
//! This is a pure-crypto test — no network, no DERP relay, no
//! `IrohTunnel::start`. We take the 32-byte secret exposed by
//! [`SpizeNativeProvider::secret_key_bytes`], feed it to
//! [`iroh::SecretKey::from_bytes`], and assert the resulting public key
//! equals [`SpizeNativeProvider::public_key_bytes`] byte-for-byte. If
//! that equality ever breaks we have a silent identity split: an agent
//! would sign wire messages under one public key while presenting a
//! different one on its Iroh connection, exactly the exploit ADR-0011
//! refuses to allow.

use std::sync::Arc;

use aex_identity::{PeerRegistry, SpizeNativeProvider};
use aex_tunnel::IrohTunnel;
use iroh::SecretKey;

#[test]
fn spize_identity_and_iroh_share_a_keypair() {
    let registry = Arc::new(PeerRegistry::new());
    let provider =
        SpizeNativeProvider::generate("acme", "alice", registry).expect("generate spize identity");

    let spize_pub = provider.public_key_bytes();

    // Canonical wiring: raw bytes → iroh SecretKey → public half.
    let iroh_secret = SecretKey::from_bytes(&provider.secret_key_bytes());
    let iroh_pub = *iroh_secret.public().as_bytes();

    assert_eq!(
        spize_pub,
        iroh_pub,
        "ADR-0011 broken: spize pub {} != iroh pub {}",
        hex::encode(spize_pub),
        hex::encode(iroh_pub)
    );
}

#[test]
fn iroh_tunnel_with_secret_key_bytes_builds() {
    // Smoke: the ergonomic builder accepts a Spize identity's raw
    // secret bytes and returns a configured IrohTunnel. We don't
    // `start()` — that requires a DERP relay and is covered by the
    // `#[ignore]` integration test in `iroh_integration.rs`.
    let registry = Arc::new(PeerRegistry::new());
    let provider =
        SpizeNativeProvider::generate("acme", "alice", registry).expect("generate spize identity");

    let _tunnel = IrohTunnel::new().with_secret_key_bytes(&provider.secret_key_bytes());
}

#[test]
fn deterministic_secret_yields_deterministic_iroh_node_id() {
    // Additional guard: given a fixed 32-byte secret, the derived Iroh
    // public key is stable across runs. This is what lets ADR-0011's
    // "Iroh NodeID == spize fingerprint source" invariant be tested
    // via golden vectors elsewhere (e.g. in the SDK test suites)
    // without invoking iroh at all.
    let fixed = [7u8; 32];
    let a = *SecretKey::from_bytes(&fixed).public().as_bytes();
    let b = *SecretKey::from_bytes(&fixed).public().as_bytes();
    assert_eq!(a, b, "iroh SecretKey::from_bytes must be deterministic");
}
