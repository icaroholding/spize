use std::sync::Arc;

use aex_core::wire::data_ticket_bytes;
use aex_data_plane::ticket::TicketError;
use aex_data_plane::{
    BlobMetadata, DataPlane, DataPlaneConfig, InMemoryBlobSource, Ticket, TicketVerifier,
};
use aex_scanner::ScanPipeline;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use tokio::sync::RwLock;

fn sign_ticket(
    signing_key: &SigningKey,
    transfer_id: &str,
    recipient: &str,
    data_plane_url: &str,
    expires: i64,
    nonce: &str,
) -> Ticket {
    let canon = data_ticket_bytes(transfer_id, recipient, data_plane_url, expires, nonce).unwrap();
    let sig = signing_key.sign(&canon);
    Ticket {
        transfer_id: transfer_id.to_string(),
        recipient: recipient.to_string(),
        data_plane_url: data_plane_url.to_string(),
        expires,
        nonce: nonce.to_string(),
        signature: hex::encode(sig.to_bytes()),
    }
}

#[tokio::test]
async fn good_ticket_verifies() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifier = TicketVerifier::new(
        signing_key.verifying_key(),
        "https://alice.tunnel.example",
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ticket = sign_ticket(
        &signing_key,
        "tx_abc123",
        "spize:acme/bob:aabbcc",
        "https://alice.tunnel.example",
        now + 60,
        "0123456789abcdef0123456789abcdef",
    );
    let verified = verifier.verify(&ticket).expect("valid ticket");
    assert_eq!(verified.transfer_id, "tx_abc123");
}

#[tokio::test]
async fn expired_ticket_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifier = TicketVerifier::new(
        signing_key.verifying_key(),
        "https://alice.tunnel.example",
    );
    let ticket = sign_ticket(
        &signing_key,
        "tx_abc123",
        "spize:acme/bob:aabbcc",
        "https://alice.tunnel.example",
        1,
        "0123456789abcdef0123456789abcdef",
    );
    assert!(matches!(verifier.verify(&ticket).unwrap_err(), TicketError::Expired { .. }));
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifier = TicketVerifier::new(
        signing_key.verifying_key(),
        "https://alice.tunnel.example",
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ticket = sign_ticket(
        &signing_key,
        "tx_abc123",
        "spize:acme/bob:aabbcc",
        "https://IMPOSTOR.tunnel.example",
        now + 60,
        "0123456789abcdef0123456789abcdef",
    );
    assert!(matches!(verifier.verify(&ticket).unwrap_err(), TicketError::WrongAudience { .. }));
}

#[tokio::test]
async fn nonce_replay_rejected() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifier = TicketVerifier::new(
        signing_key.verifying_key(),
        "https://alice.tunnel.example",
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let ticket = sign_ticket(
        &signing_key,
        "tx_abc123",
        "spize:acme/bob:aabbcc",
        "https://alice.tunnel.example",
        now + 60,
        "0123456789abcdef0123456789abcdef",
    );
    assert!(verifier.verify(&ticket).is_ok());
    assert!(matches!(verifier.verify(&ticket).unwrap_err(), TicketError::NonceReplay));
}

#[tokio::test]
async fn scanner_blocks_eicar() {
    use aex_scanner::eicar::EicarScanner;
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let pipeline = ScanPipeline::new().with_scanner(Arc::new(EicarScanner));
    let input = aex_scanner::ScanInput::new(eicar);
    let verdict = pipeline.scan(&input).await;
    assert!(verdict.is_blocking(), "EICAR should block");
}

#[tokio::test]
async fn wires_up_data_plane_struct() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifier = Arc::new(TicketVerifier::new(
        signing_key.verifying_key(),
        "https://alice.tunnel.example",
    ));
    let blobs = Arc::new(InMemoryBlobSource::new());
    blobs
        .insert(
            "tx_1".into(),
            BlobMetadata {
                size: 5,
                mime: "text/plain".into(),
                filename: "f.txt".into(),
            },
            b"hello".to_vec(),
        )
        .await;
    let cfg = DataPlaneConfig {
        blob_source: blobs,
        ticket_verifier: verifier,
        scanner: None,
        scan_cache: Arc::new(RwLock::new(Default::default())),
    };
    let dp = DataPlane::new(cfg);
    let _router = dp.router(); // compiles
}
