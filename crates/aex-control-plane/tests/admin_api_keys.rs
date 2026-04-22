//! Integration tests for `/v1/admin/api-keys` (Sprint 4 PR 4).
//!
//! Covers the CRUD surface operators use to mint, list, and revoke
//! API keys, plus the critical security invariants:
//!
//! - The plaintext `api_key` is returned ONCE at creation; subsequent
//!   GETs never expose it.
//! - The DB stores only the SHA-256 hash (we verify indirectly via
//!   the `key_prefix` column that's visible and the list endpoint
//!   that doesn't leak the hash).
//! - All endpoints are behind the admin bearer-token gate (a
//!   missing/wrong token fails before any DB work).

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_policy::TierName;
use common::TestEnv;

const ADMIN_TOKEN: &str = "aabbccddeeff00112233445566778899";

fn env_with_admin(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(ADMIN_TOKEN))
}

async fn request(
    env: &TestEnv,
    method: &str,
    path: &str,
    body: Option<Value>,
    auth: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(a) = auth {
        req = req.header("authorization", a);
    }
    let req = if let Some(b) = body {
        req.header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&b).unwrap()))
            .unwrap()
    } else {
        req.body(Body::empty()).unwrap()
    };
    let resp = env.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let json: Value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

fn bearer() -> String {
    format!("Bearer {ADMIN_TOKEN}")
}

#[sqlx::test]
async fn create_api_key_returns_plaintext_once(pool: PgPool) {
    let env = env_with_admin(pool);
    let (status, body) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({
            "customer_id": "cust_abc123",
            "name": "production server",
            "tier": "team"
        })),
        Some(&bearer()),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED, "body = {body}");

    // Shape invariants.
    assert_eq!(body["customer_id"], "cust_abc123");
    assert_eq!(body["name"], "production server");
    assert_eq!(body["tier"], "team");
    assert_eq!(body["usage_count"], 0);

    // Plaintext present on create response.
    let api_key = body["api_key"].as_str().expect("api_key plaintext present");
    assert!(api_key.starts_with("aex_live_"));
    assert_eq!(api_key.len(), 41, "aex_live_ + 32 hex = 41 chars");

    // Prefix matches the first 12 chars of the plaintext.
    let prefix = body["key_prefix"].as_str().unwrap();
    assert_eq!(prefix.len(), 12);
    assert_eq!(&api_key[..12], prefix);
}

#[sqlx::test]
async fn list_api_keys_never_leaks_plaintext_or_hash(pool: PgPool) {
    let env = env_with_admin(pool);

    // Seed two keys.
    request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c1","name":"key1","tier":"free"})),
        Some(&bearer()),
    )
    .await;
    request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c2","name":"key2","tier":"dev"})),
        Some(&bearer()),
    )
    .await;

    let (status, body) = request(&env, "GET", "/v1/admin/api-keys", None, Some(&bearer())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 2);

    for key in body["keys"].as_array().unwrap() {
        // No plaintext on the list response ever.
        assert!(
            key.get("api_key").is_none(),
            "list must NEVER expose api_key plaintext: {key}"
        );
        // And no raw hash either — customers don't need it; operators
        // would only use it to reconstruct the key, which is
        // infeasible anyway but we don't surface it.
        assert!(
            key.get("key_hash").is_none(),
            "list must NEVER expose key_hash: {key}"
        );
        // Prefix IS visible (by design — it's the searchable handle).
        assert!(key["key_prefix"].as_str().unwrap().starts_with("aex_live_"));
    }
}

#[sqlx::test]
async fn revoke_api_key_sets_revoked_at(pool: PgPool) {
    let env = env_with_admin(pool);

    let (_, created) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c","name":"n","tier":"free"})),
        Some(&bearer()),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    // Pre-revoke: revoked_at is null → serde-skipped → field absent.
    assert!(created.get("revoked_at").is_none());

    let (status, revoked) = request(
        &env,
        "DELETE",
        &format!("/v1/admin/api-keys/{id}"),
        None,
        Some(&bearer()),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        revoked["revoked_at"].is_string(),
        "revoked_at must be populated after DELETE: {revoked}"
    );
}

#[sqlx::test]
async fn revoke_is_idempotent(pool: PgPool) {
    // Revoking an already-revoked key returns 200 with the original
    // revoked_at — we deliberately don't bump the timestamp forward.
    let env = env_with_admin(pool);

    let (_, created) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c","name":"n","tier":"free"})),
        Some(&bearer()),
    )
    .await;
    let id = created["id"].as_str().unwrap();

    let (s1, body1) = request(
        &env,
        "DELETE",
        &format!("/v1/admin/api-keys/{id}"),
        None,
        Some(&bearer()),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);
    let first_revoke = body1["revoked_at"].as_str().unwrap().to_string();

    let (s2, body2) = request(
        &env,
        "DELETE",
        &format!("/v1/admin/api-keys/{id}"),
        None,
        Some(&bearer()),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(
        body2["revoked_at"].as_str().unwrap(),
        first_revoke,
        "second revoke must return the ORIGINAL revoked_at, not now()"
    );
}

#[sqlx::test]
async fn revoke_unknown_id_returns_404(pool: PgPool) {
    let env = env_with_admin(pool);
    let bogus = "00000000-0000-0000-0000-000000000000";
    let (status, body) = request(
        &env,
        "DELETE",
        &format!("/v1/admin/api-keys/{bogus}"),
        None,
        Some(&bearer()),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "not_found");
}

#[sqlx::test]
async fn reject_empty_fields_with_400(pool: PgPool) {
    let env = env_with_admin(pool);
    for bad in [
        json!({"customer_id":"","name":"n","tier":"free"}),
        json!({"customer_id":"c","name":"","tier":"free"}),
        json!({"customer_id":"c","name":"n","tier":""}),
    ] {
        let (status, _) = request(
            &env,
            "POST",
            "/v1/admin/api-keys",
            Some(bad),
            Some(&bearer()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[sqlx::test]
async fn api_keys_endpoints_require_admin_token(pool: PgPool) {
    // Every endpoint under /v1/admin/api-keys MUST sit behind the
    // same bearer gate. Regression guard: if someone later mounts
    // an api-keys route on the wrong parent router, this catches
    // it immediately.
    let env = env_with_admin(pool);

    // No header → 401.
    let (s, _) = request(&env, "GET", "/v1/admin/api-keys", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    let (s, _) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c","name":"n","tier":"free"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // Wrong token → 403.
    let (s, _) = request(
        &env,
        "GET",
        "/v1/admin/api-keys",
        None,
        Some("Bearer ffeeddccbbaa99887766554433221100"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[sqlx::test]
async fn distinct_creates_produce_distinct_plaintexts(pool: PgPool) {
    // Regression guard: the CSPRNG is fresh per call, so two keys
    // minted in quick succession have different plaintexts. A bug
    // that cached entropy would fail this assertion.
    let env = env_with_admin(pool);

    let (_, a) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c","name":"n","tier":"free"})),
        Some(&bearer()),
    )
    .await;
    let (_, b) = request(
        &env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({"customer_id":"c","name":"n","tier":"free"})),
        Some(&bearer()),
    )
    .await;

    assert_ne!(a["api_key"].as_str(), b["api_key"].as_str());
    assert_ne!(a["key_prefix"].as_str(), b["key_prefix"].as_str());
    assert_ne!(a["id"].as_str(), b["id"].as_str());
}
