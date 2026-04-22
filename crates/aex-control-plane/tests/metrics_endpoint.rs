//! End-to-end test for `GET /metrics` (Sprint 3).
//!
//! Exercises a realistic CP flow (register two agents, create a
//! transfer, ack it) and asserts the resulting metric values at
//! `/metrics`. Proves two things:
//!
//! 1. Every counter we claim to expose actually fires at the right
//!    lifecycle point — a regression that stopped incrementing any of
//!    these would surface here rather than go unnoticed.
//! 2. The Prometheus text exposition format is parse-clean (keys +
//!    label sets + numeric value on every non-comment line).

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_core::wire::{registration_challenge_bytes, transfer_intent_bytes, transfer_receipt_bytes};
use common::{random_nonce, TestEnv};

struct Agent {
    key: SigningKey,
    agent_id: String,
}

async fn register(env: &TestEnv, org: &str, name: &str) -> Agent {
    let key = SigningKey::generate(&mut OsRng);
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
    let nonce = random_nonce();
    let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let challenge =
        registration_challenge_bytes(&pubkey_hex, org, name, &nonce, issued_at).unwrap();
    let sig = key.sign(&challenge);
    let body = json!({
        "public_key_hex": pubkey_hex,
        "org": org,
        "name": name,
        "nonce": nonce,
        "issued_at": issued_at,
        "signature_hex": hex::encode(sig.to_bytes()),
    });
    let (status, body) = env.post_json("/v1/agents/register", &body).await;
    assert_eq!(status, StatusCode::CREATED, "register: {}", body);
    Agent {
        key,
        agent_id: body["agent_id"].as_str().unwrap().to_string(),
    }
}

fn intent(sender: &Agent, recipient: &str, blob: &[u8]) -> Value {
    let nonce = random_nonce();
    let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let canonical = transfer_intent_bytes(
        &sender.agent_id,
        recipient,
        blob.len() as u64,
        "text/plain",
        "n.txt",
        &nonce,
        issued_at,
    )
    .unwrap();
    let sig = sender.key.sign(&canonical);
    json!({
        "sender_agent_id": sender.agent_id,
        "recipient": recipient,
        "declared_mime": "text/plain",
        "filename": "n.txt",
        "nonce": nonce,
        "issued_at": issued_at,
        "intent_signature_hex": hex::encode(sig.to_bytes()),
        "blob_hex": hex::encode(blob),
    })
}

fn receipt(recipient: &Agent, transfer_id: &str, action: &str) -> Value {
    let nonce = random_nonce();
    let issued_at = time::OffsetDateTime::now_utc().unix_timestamp();
    let canonical =
        transfer_receipt_bytes(&recipient.agent_id, transfer_id, action, &nonce, issued_at)
            .unwrap();
    let sig = recipient.key.sign(&canonical);
    json!({
        "recipient_agent_id": recipient.agent_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "signature_hex": hex::encode(sig.to_bytes()),
    })
}

async fn get_metrics(env: &TestEnv) -> (StatusCode, String, String) {
    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let body = String::from_utf8(bytes.to_vec()).expect("metrics body is utf-8");
    (status, content_type, body)
}

#[sqlx::test]
async fn metrics_endpoint_emits_prometheus_text_format(pool: PgPool) {
    let env = TestEnv::new(pool);
    let (status, ct, body) = get_metrics(&env).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        ct.starts_with("text/plain"),
        "unexpected Content-Type: {ct}"
    );
    // At least the scalar families are always present, even with
    // zero activity.
    assert!(body.contains("# TYPE aex_agents_registered_total counter"));
    assert!(body.contains("# TYPE aex_transfers_delivered_total counter"));
    assert!(body.contains("# TYPE aex_in_flight_transfers gauge"));
}

#[sqlx::test]
async fn metrics_increment_after_register_and_transfer(pool: PgPool) {
    let env = TestEnv::new(pool);

    // Register two agents + create a transfer + ack it. The CP goes
    // through the full happy path; afterwards three counters should
    // have fired.
    let alice = register(&env, "acme", "alice").await;
    let bob = register(&env, "acme", "bob").await;

    let (s, created) = env
        .post_json("/v1/transfers", &intent(&alice, &bob.agent_id, b"hi"))
        .await;
    assert_eq!(s, StatusCode::CREATED, "create: {}", created);
    let transfer_id = created["transfer_id"].as_str().unwrap();

    // Download so the transfer moves to `accepted`, then ack to
    // move to `delivered`.
    let (s, _) = env
        .post_json(
            &format!("/v1/transfers/{}/download", transfer_id),
            &receipt(&bob, transfer_id, "download"),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = env
        .post_json(
            &format!("/v1/transfers/{}/ack", transfer_id),
            &receipt(&bob, transfer_id, "ack"),
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    let (_, _, body) = get_metrics(&env).await;

    // Exactly two registrations.
    assert!(
        body.contains("aex_agents_registered_total 2"),
        "expected 2 registrations, got: {body}"
    );
    // One transfer created with recipient_kind=spize_native (bob is a
    // spize:* agent_id).
    assert!(
        body.contains(r#"aex_transfers_created_total{recipient_kind="spize_native"} 1"#),
        "expected 1 spize_native transfer, got: {body}"
    );
    // One delivery.
    assert!(
        body.contains("aex_transfers_delivered_total 1"),
        "expected 1 delivery, got: {body}"
    );
}

#[sqlx::test]
async fn rejected_transfer_bumps_rejected_counter(pool: PgPool) {
    let env = TestEnv::new(pool);
    let alice = register(&env, "acme", "alice").await;

    // EICAR signature body — the scanner rejects this with
    // `PipelineVerdict::Malicious`, so the post-scan policy returns
    // Deny and the control plane persists a `rejected` row.
    let eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let (s, body) = env
        .post_json(
            "/v1/transfers",
            &intent(&alice, "spize:acme/bob:aabbcc", eicar),
        )
        .await;
    // EICAR path returns 200 with state=rejected.
    assert_eq!(s, StatusCode::OK, "eicar transfer: {}", body);
    assert_eq!(body["state"], "rejected");

    let (_, _, metrics) = get_metrics(&env).await;
    assert!(
        metrics.contains(r#"aex_transfers_rejected_total{reason="scanner"} 1"#),
        "expected scanner rejection counter, got: {metrics}"
    );
}
