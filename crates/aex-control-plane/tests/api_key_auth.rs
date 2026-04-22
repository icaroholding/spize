//! Integration tests for the `/v1/metered/*` auth middleware
//! (Sprint 4 PR 5).
//!
//! Covers the customer-facing authentication surface:
//!
//! - Valid key on `X-API-Key` or `Authorization: Bearer` → 200.
//! - Missing header → 401 with the `api-key-missing.md` runbook URL.
//! - Malformed / unknown / revoked key → 401 with the
//!   `api-key-invalid.md` runbook URL.
//! - A successful call bumps `usage_count` and `last_used_at`
//!   (fire-and-forget; verified via polling since the UPDATE is
//!   async relative to the response).

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_policy::TierName;
use common::TestEnv;

const ADMIN_TOKEN: &str = "aabbccddeeff00112233445566778899";

fn env(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(ADMIN_TOKEN))
}

fn admin_bearer() -> String {
    format!("Bearer {ADMIN_TOKEN}")
}

/// Build + execute a one-shot request and parse the JSON body.
async fn request(
    env: &TestEnv,
    method: &str,
    path: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        req = req.header(*name, *value);
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

/// Mint a fresh API key through the admin surface. Returns
/// `(id, plaintext)`. Tests use the plaintext to exercise the
/// middleware and the id to verify DB-side state post-call.
async fn mint_key(env: &TestEnv, customer_id: &str, tier: &str) -> (String, String) {
    let admin = admin_bearer();
    let (status, body) = request(
        env,
        "POST",
        "/v1/admin/api-keys",
        Some(json!({
            "customer_id": customer_id,
            "name": "auth-test",
            "tier": tier,
        })),
        &[("authorization", &admin)],
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "mint failed: {body}");
    let id = body["id"].as_str().unwrap().to_string();
    let plaintext = body["api_key"].as_str().unwrap().to_string();
    (id, plaintext)
}

/// Fetch one row from the admin list endpoint, looked up by id.
/// Used to poll the post-call DB state when the middleware bump
/// hasn't landed yet.
async fn fetch_key_row(env: &TestEnv, id: &str) -> Value {
    let admin = admin_bearer();
    let (_, body) = request(
        env,
        "GET",
        "/v1/admin/api-keys",
        None,
        &[("authorization", &admin)],
    )
    .await;
    body["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["id"].as_str() == Some(id))
        .cloned()
        .expect("key id must be present in admin list")
}

/// Poll the admin list until `predicate` returns true on the row,
/// or `timeout_ms` elapses. Returns the latest row seen. Used to
/// wait for the fire-and-forget usage bump to land without sleeping
/// a fixed amount and flaking on slow runners.
async fn wait_for<F>(env: &TestEnv, id: &str, timeout_ms: u64, predicate: F) -> Value
where
    F: Fn(&Value) -> bool,
{
    let start = std::time::Instant::now();
    let mut row = fetch_key_row(env, id).await;
    while !predicate(&row) {
        if start.elapsed().as_millis() as u64 > timeout_ms {
            return row;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        row = fetch_key_row(env, id).await;
    }
    row
}

// ---------- Positive cases ----------

#[sqlx::test]
async fn valid_key_on_x_api_key_header_returns_200(pool: PgPool) {
    let env = env(pool);
    let (_, plaintext) = mint_key(&env, "cust_xapi", "dev").await;

    let (status, body) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("x-api-key", &plaintext)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body = {body}");
    assert_eq!(body["customer_id"], "cust_xapi");
    assert_eq!(body["tier"], "dev");
    assert_eq!(body["key_prefix"], &plaintext[..12]);
    assert!(
        body.get("api_key").is_none(),
        "whoami must never echo the plaintext: {body}"
    );
}

#[sqlx::test]
async fn valid_key_on_authorization_bearer_returns_200(pool: PgPool) {
    let env = env(pool);
    let (_, plaintext) = mint_key(&env, "cust_bearer", "team").await;

    let bearer = format!("Bearer {plaintext}");
    let (status, body) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("authorization", &bearer)],
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body = {body}");
    assert_eq!(body["customer_id"], "cust_bearer");
    assert_eq!(body["tier"], "team");
}

// ---------- Negative cases ----------

#[sqlx::test]
async fn missing_header_returns_401_with_missing_runbook(pool: PgPool) {
    let env = env(pool);
    let (status, body) = request(&env, "GET", "/v1/metered/whoami", None, &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "unauthorized");
    let url = body["runbook_url"].as_str().expect("runbook_url present");
    assert!(url.ends_with("api-key-missing.md"), "got: {url}");
}

#[sqlx::test]
async fn malformed_header_returns_401_with_invalid_runbook(pool: PgPool) {
    let env = env(pool);
    for bad in [
        "aex_test_0123456789abcdef0123456789abcdef", // wrong prefix
        "aex_live_shortkey",                         // wrong length
        "totally-not-a-key",                         // no prefix at all
    ] {
        let (status, body) = request(
            &env,
            "GET",
            "/v1/metered/whoami",
            None,
            &[("x-api-key", bad)],
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "for input {bad}");
        let url = body["runbook_url"].as_str().expect("runbook_url present");
        assert!(url.ends_with("api-key-invalid.md"), "for {bad}: got {url}");
    }
}

#[sqlx::test]
async fn unknown_but_well_formed_key_returns_401_with_invalid_runbook(pool: PgPool) {
    // Well-formed plaintext that was never minted — passes the
    // shape check but misses the DB lookup.
    let env = env(pool);
    let bogus = "aex_live_deadbeefdeadbeefdeadbeefdeadbeef";
    let (status, body) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("x-api-key", bogus)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let url = body["runbook_url"].as_str().expect("runbook_url present");
    assert!(url.ends_with("api-key-invalid.md"), "got: {url}");
}

#[sqlx::test]
async fn revoked_key_is_rejected_like_unknown(pool: PgPool) {
    // Proves the partial index filter holds end-to-end: a revoked
    // key behaves identically to an unknown one at the wire (no
    // leak of revocation status).
    let env = env(pool);
    let (id, plaintext) = mint_key(&env, "cust_rev", "free").await;

    // Revoke via admin.
    let admin = admin_bearer();
    let (s, _) = request(
        &env,
        "DELETE",
        &format!("/v1/admin/api-keys/{id}"),
        None,
        &[("authorization", &admin)],
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    // Now the same plaintext must fail metered auth.
    let (status, body) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("x-api-key", &plaintext)],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let url = body["runbook_url"].as_str().expect("runbook_url present");
    assert!(url.ends_with("api-key-invalid.md"), "got: {url}");
}

// ---------- Usage bump ----------

#[sqlx::test]
async fn successful_call_bumps_usage_count(pool: PgPool) {
    let env = env(pool);
    let (id, plaintext) = mint_key(&env, "cust_bump", "dev").await;

    // Pre-call: counter is 0 (see migration default).
    let pre = fetch_key_row(&env, &id).await;
    assert_eq!(pre["usage_count"].as_i64().unwrap(), 0);

    let (status, _) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("x-api-key", &plaintext)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // The bump is fire-and-forget — poll with a 2s ceiling.
    let post = wait_for(&env, &id, 2000, |row| {
        row["usage_count"].as_i64().unwrap_or(0) >= 1
    })
    .await;
    assert_eq!(
        post["usage_count"].as_i64().unwrap(),
        1,
        "usage_count must reach 1 within timeout: {post}"
    );
}

#[sqlx::test]
async fn successful_call_sets_last_used_at(pool: PgPool) {
    let env = env(pool);
    let (id, plaintext) = mint_key(&env, "cust_lastused", "dev").await;

    // Pre-call: last_used_at is null → serde-skipped → field absent.
    let pre = fetch_key_row(&env, &id).await;
    assert!(pre.get("last_used_at").is_none());

    let (status, _) = request(
        &env,
        "GET",
        "/v1/metered/whoami",
        None,
        &[("x-api-key", &plaintext)],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let post = wait_for(&env, &id, 2000, |row| {
        row.get("last_used_at").and_then(|v| v.as_str()).is_some()
    })
    .await;
    assert!(
        post["last_used_at"].is_string(),
        "last_used_at must be populated within timeout: {post}"
    );
}
