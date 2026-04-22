//! End-to-end test for Sprint 3 Delight #3: error responses carry a
//! `runbook_url` field pointing at an operator-facing remediation page.
//!
//! Exercises the full CP stack (route → handler → ApiError → JSON
//! serialization) so a regression in any of those layers trips this
//! test rather than silently dropping the field.

mod common;

use axum::http::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;

use common::TestEnv;

#[sqlx::test]
async fn unauthorized_error_body_includes_runbook_url(pool: PgPool) {
    let env = TestEnv::new(pool);
    // POST /v1/agents/register with a malformed signature hex string →
    // handler rejects with 400 BadRequest (hex decode fails). Not
    // ideal for an unauthorized runbook test — let's use a real
    // mismatched signature instead via register with the wrong key.
    // Simpler path: hit /v1/inbox with a pubkey_hex that doesn't match
    // the canonical — 401 with "no active key" which maps to the
    // agent-not-registered runbook.

    let payload = json!({
        "recipient_agent_id": "spize:acme/ghost:aabbcc",
        "nonce": "0123456789abcdef0123456789abcdef",
        "issued_at": time::OffsetDateTime::now_utc().unix_timestamp(),
        "signature_hex": "00".repeat(64),
    });
    let (status, body) = env.post_json("/v1/inbox", &payload).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let runbook = body
        .get("runbook_url")
        .and_then(Value::as_str)
        .expect("unauthorized body must include runbook_url");
    assert!(
        runbook.ends_with("agent-not-registered-or-revoked.md"),
        "unexpected runbook URL: {runbook}"
    );
    assert!(
        runbook.starts_with("https://github.com/icaroholding/aex/blob/master/docs/runbooks/"),
        "runbook URL must be a github blob link, got: {runbook}"
    );
}

#[sqlx::test]
async fn bad_request_without_specific_runbook_omits_field(pool: PgPool) {
    let env = TestEnv::new(pool);

    // A 400 that doesn't match any specific runbook keyword — the
    // error body should NOT include runbook_url (additive field
    // serde-skipped when None).
    let payload = json!({
        "public_key_hex": "deadbeef",  // wrong length — triggers
                                        // "expected 32 bytes" which
                                        // doesn't match any keyword.
        "org": "acme",
        "name": "alice",
        "nonce": "0123456789abcdef0123456789abcdef",
        "issued_at": time::OffsetDateTime::now_utc().unix_timestamp(),
        "signature_hex": "00".repeat(64),
    });
    let (status, body) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // The "expected 32 bytes" message doesn't match any specific
    // runbook keyword → field is omitted entirely.
    assert!(
        body.get("runbook_url").is_none(),
        "generic bad_request must not fabricate a runbook: {body:?}"
    );
}

#[sqlx::test]
async fn clock_skew_rejection_points_at_clock_runbook(pool: PgPool) {
    let env = TestEnv::new(pool);
    // Build a register payload with a wildly stale timestamp — the
    // freshness check rejects it at 400 before any crypto runs. The
    // resulting error message contains "issued_at" which maps to
    // the clock-skew runbook.
    let stale_ts = time::OffsetDateTime::now_utc().unix_timestamp() - 10_000;
    let payload = json!({
        "public_key_hex": "aa".repeat(32),
        "org": "acme",
        "name": "alice",
        "nonce": "0123456789abcdef0123456789abcdef",
        "issued_at": stale_ts,
        "signature_hex": "00".repeat(64),
    });
    let (status, body) = env.post_json("/v1/agents/register", &payload).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let runbook = body
        .get("runbook_url")
        .and_then(Value::as_str)
        .expect("clock skew body must include runbook_url");
    assert!(
        runbook.ends_with("clock-skew.md"),
        "unexpected runbook: {runbook}"
    );
}
