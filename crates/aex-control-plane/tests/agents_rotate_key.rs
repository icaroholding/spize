//! End-to-end tests for the key-rotation flow (ADR-0024).
//!
//! Uses a [`FrozenClock`] so we can deterministically step across the
//! 24h grace boundary without sleeping. Also includes the decision
//! TODO-2 concurrent race test: two simultaneous rotate-key calls for
//! the same agent must produce exactly one new current key.
//!
//! Requires `DATABASE_URL` to point at a live Postgres instance. During
//! local dev, run `docker compose -f deploy/docker-compose.dev.yml up -d`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use axum::Router;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_audit::MemoryAuditLog;
use aex_control_plane::{
    blob::MemoryBlobStore,
    build_app,
    clock::{Clock, FrozenClock},
    AppState,
};
use aex_core::wire::{
    registration_challenge_bytes, rotate_key_challenge_bytes, transfer_receipt_bytes,
};
use aex_policy::{TierName, TierPolicy};
use aex_scanner::{
    eicar::EicarScanner, injection::RegexInjectionScanner, magic::MagicByteScanner,
    size::SizeLimitScanner, ScanPipeline,
};
use common::random_nonce;

/// Test harness that owns both the Router and the FrozenClock so tests
/// can advance time without threading extra state around.
struct RotateEnv {
    app: Router,
    clock: Arc<FrozenClock>,
}

impl RotateEnv {
    fn new(pool: PgPool, initial_unix: i64) -> Self {
        let scanner = ScanPipeline::new()
            .with_scanner(Arc::new(SizeLimitScanner::new(50 * 1024 * 1024)))
            .with_scanner(Arc::new(MagicByteScanner::new()))
            .with_scanner(Arc::new(EicarScanner::new()))
            .with_scanner(Arc::new(RegexInjectionScanner::new()));
        let clock = Arc::new(FrozenClock::new(initial_unix));
        let state = AppState::new(
            pool,
            scanner,
            Arc::new(TierPolicy::for_tier(TierName::Dev)),
            Arc::new(MemoryAuditLog::new()),
            Arc::new(MemoryBlobStore::new()),
        )
        .with_clock(clock.clone() as Arc<dyn Clock>);
        Self {
            app: build_app(state),
            clock,
        }
    }

    async fn request(&self, request: Request<Body>) -> (StatusCode, Value) {
        let resp = self.app.clone().oneshot(request).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 256 * 1024 * 1024).await.unwrap();
        let json: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, json)
    }

    async fn post_json(&self, path: &str, body: &Value) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        self.request(req).await
    }

    fn now_unix(&self) -> i64 {
        self.clock.now_unix()
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }
}

async fn register(env: &RotateEnv, key: &SigningKey, org: &str, name: &str) -> String {
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
    let nonce = random_nonce();
    let issued_at = env.now_unix();
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
    assert_eq!(status, StatusCode::CREATED, "register failed: {}", body);
    body["agent_id"].as_str().unwrap().to_string()
}

fn build_rotate_payload(
    agent_id: &str,
    old_key: &SigningKey,
    new_key: &SigningKey,
    now_unix: i64,
) -> Value {
    let old_pub = hex::encode(old_key.verifying_key().to_bytes());
    let new_pub = hex::encode(new_key.verifying_key().to_bytes());
    let nonce = random_nonce();
    let canonical =
        rotate_key_challenge_bytes(agent_id, &old_pub, &new_pub, &nonce, now_unix).unwrap();
    let sig = old_key.sign(&canonical);
    json!({
        "agent_id": agent_id,
        "new_public_key_hex": new_pub,
        "nonce": nonce,
        "issued_at": now_unix,
        "signature_hex": hex::encode(sig.to_bytes()),
    })
}

/// Sign an inbox receipt with a specific key, as the given agent. Used
/// to prove a key verifies (OK) or does not (UNAUTHORIZED) against the
/// grace-period verifier.
fn inbox_payload(agent_id: &str, key: &SigningKey, now_unix: i64) -> Value {
    let nonce = random_nonce();
    let canonical = transfer_receipt_bytes(agent_id, "inbox", "inbox", &nonce, now_unix).unwrap();
    let sig = key.sign(&canonical);
    json!({
        "recipient_agent_id": agent_id,
        "nonce": nonce,
        "issued_at": now_unix,
        "signature_hex": hex::encode(sig.to_bytes()),
    })
}

// ----------------------------- happy path -----------------------------

#[sqlx::test]
async fn rotate_key_happy_path(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);

    let agent_id = register(&env, &old_key, "acme", "alice").await;

    // Old key verifies BEFORE rotation.
    let inbox = inbox_payload(&agent_id, &old_key, env.now_unix());
    let (s, _) = env.post_json("/v1/inbox", &inbox).await;
    assert_eq!(s, StatusCode::OK, "old key must verify pre-rotation");

    // Rotate.
    let payload = build_rotate_payload(&agent_id, &old_key, &new_key, env.now_unix());
    let (status, body) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(status, StatusCode::OK, "rotate failed: {}", body);
    assert_eq!(
        body["new_public_key_hex"],
        hex::encode(new_key.verifying_key().to_bytes())
    );
    let grace_end = body["previous_key_valid_until"].as_i64().unwrap();
    assert!(grace_end > env.now_unix());
    assert_eq!(grace_end - env.now_unix(), 24 * 60 * 60);
}

#[sqlx::test]
async fn rotate_key_both_keys_verify_in_grace(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &old_key, "acme", "alice").await;

    let payload = build_rotate_payload(&agent_id, &old_key, &new_key, env.now_unix());
    let (s, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(s, StatusCode::OK);

    // Step forward 1h — still inside the 24h grace.
    env.advance(Duration::from_secs(3600));

    // Old key STILL verifies (grace).
    let old_inbox = inbox_payload(&agent_id, &old_key, env.now_unix());
    let (s, _) = env.post_json("/v1/inbox", &old_inbox).await;
    assert_eq!(s, StatusCode::OK, "old key must verify during grace");

    // New key verifies.
    let new_inbox = inbox_payload(&agent_id, &new_key, env.now_unix());
    let (s, _) = env.post_json("/v1/inbox", &new_inbox).await;
    assert_eq!(s, StatusCode::OK, "new key must verify during grace");
}

#[sqlx::test]
async fn rotate_key_only_new_verifies_after_grace(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &old_key, "acme", "alice").await;

    let payload = build_rotate_payload(&agent_id, &old_key, &new_key, env.now_unix());
    let (s, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(s, StatusCode::OK);

    // Jump 25h into the future — past the 24h grace.
    env.advance(Duration::from_secs(25 * 60 * 60));

    // Old key NO LONGER verifies.
    let old_inbox = inbox_payload(&agent_id, &old_key, env.now_unix());
    let (s, _) = env.post_json("/v1/inbox", &old_inbox).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "old key must NOT verify after grace"
    );

    // New key still verifies.
    let new_inbox = inbox_payload(&agent_id, &new_key, env.now_unix());
    let (s, _) = env.post_json("/v1/inbox", &new_inbox).await;
    assert_eq!(s, StatusCode::OK, "new key must verify after grace");
}

// ------------------------------ security ------------------------------

#[sqlx::test]
async fn rotate_key_requires_current_key_signature(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let alice_key = SigningKey::generate(&mut OsRng);
    let impostor = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);

    let agent_id = register(&env, &alice_key, "acme", "alice").await;

    // Impostor signs the rotate challenge. Canonical bytes still use
    // alice's CURRENT public key (old_pub) so the CP rebuilds the same
    // challenge and rejects the signature.
    let payload = build_rotate_payload(&agent_id, &impostor, &new_key, env.now_unix());
    let (status, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn rotate_key_nonce_replay_rejected(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &old_key, "acme", "alice").await;

    let payload = build_rotate_payload(&agent_id, &old_key, &new_key, env.now_unix());
    let (s1, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(s1, StatusCode::OK);

    // Same payload twice. After the first rotation alice's current
    // key IS the new_key: the server's rebuilt canonical bytes now
    // have old_pub == new_pub, which trips the "must differ" check
    // (400) before any signature math — so we accept 400 too. The
    // non-negotiable invariant is that the replay MUST NOT succeed.
    let (s2, body) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert!(
        matches!(
            s2,
            StatusCode::BAD_REQUEST | StatusCode::UNAUTHORIZED | StatusCode::CONFLICT
        ),
        "replay must not succeed: {} {}",
        s2,
        body
    );
}

#[sqlx::test]
async fn rotate_key_same_new_and_current_rejected(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let key = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &key, "acme", "alice").await;

    // Hand-roll a payload that rotates TO the same key. We bypass
    // `rotate_key_challenge_bytes` because the helper enforces
    // "old != new" on the way in — the point of this test is to
    // confirm the server ALSO refuses it, in case a buggy/malicious
    // client posts bytes that the helper would refuse.
    let pub_hex = hex::encode(key.verifying_key().to_bytes());
    let nonce = random_nonce();
    let issued_at = env.now_unix();
    let canonical = format!(
        "spize-rotate-key:v1\nagent={}\nold_pub={}\nnew_pub={}\nnonce={}\nts={}",
        agent_id, pub_hex, pub_hex, nonce, issued_at
    );
    let sig = key.sign(canonical.as_bytes());
    let payload = json!({
        "agent_id": agent_id,
        "new_public_key_hex": pub_hex,
        "nonce": nonce,
        "issued_at": issued_at,
        "signature_hex": hex::encode(sig.to_bytes()),
    });
    let (status, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[sqlx::test]
async fn rotate_key_unknown_agent_returns_404(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);

    let payload = build_rotate_payload(
        "spize:acme/ghost:aabbcc",
        &old_key,
        &new_key,
        env.now_unix(),
    );
    let (status, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[sqlx::test]
async fn rotate_key_stale_timestamp_rejected(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let old_key = SigningKey::generate(&mut OsRng);
    let new_key = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &old_key, "acme", "alice").await;

    // Sign with a timestamp 10k seconds ago — outside the 300s skew.
    let stale_ts = env.now_unix() - 10_000;
    let payload = build_rotate_payload(&agent_id, &old_key, &new_key, stale_ts);
    let (status, _) = env.post_json("/v1/agents/rotate-key", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

// --------------------------- rotation chain ---------------------------

#[sqlx::test]
async fn rotate_key_twice_establishes_new_current(pool: PgPool) {
    let env = RotateEnv::new(pool, 1_800_000_000);
    let k1 = SigningKey::generate(&mut OsRng);
    let k2 = SigningKey::generate(&mut OsRng);
    let k3 = SigningKey::generate(&mut OsRng);
    let agent_id = register(&env, &k1, "acme", "alice").await;

    // k1 → k2
    let p1 = build_rotate_payload(&agent_id, &k1, &k2, env.now_unix());
    let (s, _) = env.post_json("/v1/agents/rotate-key", &p1).await;
    assert_eq!(s, StatusCode::OK);

    // Jump past the first grace so k1 is dead; k2 should be the sole
    // current key now.
    env.advance(Duration::from_secs(25 * 60 * 60));

    // k2 → k3 (authorised by k2, the new current).
    let p2 = build_rotate_payload(&agent_id, &k2, &k3, env.now_unix());
    let (s, body) = env.post_json("/v1/agents/rotate-key", &p2).await;
    assert_eq!(s, StatusCode::OK, "second rotation failed: {}", body);
}

// -------------------------- concurrent race --------------------------

/// Two concurrent `rotate-key` calls against the same agent. Exactly
/// one must succeed; the other must get a deterministic conflict
/// (401 for stale-current-key or 409 for the UNIQUE collision /
/// serialise-out case). The outcome we MUST NOT allow is "both 200 OK"
/// — that would mean two NULL-valid_to rows exist for one agent.
///
/// Staged with a [`tokio::sync::Barrier`] so both calls enter the
/// handler at the same instant, not back-to-back.
#[sqlx::test]
async fn concurrent_rotate_key_race(pool: PgPool) {
    use tokio::sync::Barrier;

    // Construct the env once, then share `app` via Arc so two tasks
    // can hit it simultaneously.
    let env = Arc::new(RotateEnv::new(pool, 1_800_000_000));
    let old_key = SigningKey::generate(&mut OsRng);
    let new_a = SigningKey::generate(&mut OsRng);
    let new_b = SigningKey::generate(&mut OsRng);

    let agent_id = register(&env, &old_key, "acme", "alice").await;

    let p_a = build_rotate_payload(&agent_id, &old_key, &new_a, env.now_unix());
    let p_b = build_rotate_payload(&agent_id, &old_key, &new_b, env.now_unix());

    let barrier = Arc::new(Barrier::new(2));

    let env_a = env.clone();
    let barrier_a = barrier.clone();
    let call_a = tokio::spawn(async move {
        barrier_a.wait().await;
        env_a.post_json("/v1/agents/rotate-key", &p_a).await
    });

    let env_b = env.clone();
    let barrier_b = barrier.clone();
    let call_b = tokio::spawn(async move {
        barrier_b.wait().await;
        env_b.post_json("/v1/agents/rotate-key", &p_b).await
    });

    let (r_a, r_b) = tokio::join!(call_a, call_b);
    let (s_a, _) = r_a.unwrap();
    let (s_b, _) = r_b.unwrap();

    // Exactly one 200 OK; the other is a conflict-ish error. The
    // loser's specific status depends on how the race interleaved
    // (UPDATE serialise-out → 409; or new.Current read after old.close
    // → 401/NotFound), so accept any of the expected failure codes.
    let ok_count = [s_a, s_b].iter().filter(|s| **s == StatusCode::OK).count();
    assert_eq!(
        ok_count, 1,
        "expected exactly one 200 OK; got s_a={} s_b={}",
        s_a, s_b
    );
    let loser = if s_a == StatusCode::OK { s_b } else { s_a };
    assert!(
        matches!(
            loser,
            StatusCode::CONFLICT | StatusCode::UNAUTHORIZED | StatusCode::NOT_FOUND
        ),
        "loser status must be 401/404/409, got {}",
        loser
    );
}
