//! End-to-end tests for `/v1/customer/*` (Sprint 4 PR 7).
//!
//! Each test runs against an in-memory app using a real Postgres
//! pool seeded with `customers` + `subscriptions` rows that mirror
//! what the Stripe webhook would have populated. The session
//! middleware validates JWTs the test mints inline, so we don't
//! need a working email round-trip to exercise the authenticated
//! endpoints.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sqlx::PgPool;
use tower::ServiceExt;

use aex_control_plane::{
    clock::FrozenClock,
    config::{CustomerAuthConfig, EmailConfig},
    session,
};
use aex_policy::TierName;
use common::TestEnv;

const SESSION_SECRET: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const FRONTEND_BASE_URL: &str = "https://spize.io";
const FROZEN_NOW: i64 = 1_700_000_000;

// ----------------------------- helpers -----------------------------

fn env(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| {
        s.with_customer_auth(CustomerAuthConfig {
            session_secret: Some(SESSION_SECRET.into()),
            frontend_base_url: Some(FRONTEND_BASE_URL.into()),
        })
        .with_email(EmailConfig {
            // No RESEND_API_KEY → magic-link request returns the
            // token in the response body so the verify path is
            // exercisable without a working SMTP loop.
            resend_api_key: None,
            mail_from: "Spize <noreply@spize.io>".into(),
        })
        .with_clock(Arc::new(FrozenClock::new(FROZEN_NOW)))
    })
}

async fn seed_customer_with_subscription(
    pool: &PgPool,
    customer_id: &str,
    email: &str,
    tier: &str,
) {
    let mut tx = pool.begin().await.unwrap();
    aex_control_plane::db::customers::upsert_in_tx(&mut tx, customer_id, email)
        .await
        .unwrap();
    aex_control_plane::db::subscriptions::upsert_in_tx(
        &mut tx,
        customer_id,
        &format!("sub_{customer_id}"),
        tier,
        "active",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

async fn seed_customer_only(pool: &PgPool, customer_id: &str, email: &str) {
    let mut tx = pool.begin().await.unwrap();
    aex_control_plane::db::customers::upsert_in_tx(&mut tx, customer_id, email)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

async fn post_json(env: &TestEnv, path: &str, body: Value) -> (StatusCode, Value, Vec<String>) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    request(env, req).await
}

async fn request(env: &TestEnv, req: Request<Body>) -> (StatusCode, Value, Vec<String>) {
    let resp = env.app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let cookies: Vec<String> = resp
        .headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(String::from))
        .collect();
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json, cookies)
}

/// Mint a session cookie value directly (bypassing magic-link) for
/// tests that exercise the api-keys endpoints. Uses wall-clock now
/// so the JWT verifies against `jsonwebtoken`'s internal clock —
/// see the `session_now` comment in `customer/auth.rs` for the same
/// asymmetry between AppState.clock and JWT validation time.
fn issue_session_cookie(customer_id: &str) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = session::issue(SESSION_SECRET, customer_id, 3600, now).unwrap();
    format!("{}={}", session::COOKIE_NAME, token)
}

async fn authed_get(env: &TestEnv, path: &str, cookie: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let (s, j, _) = request(env, req).await;
    (s, j)
}

async fn authed_post(env: &TestEnv, path: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("POST")
        .uri(path)
        .header("cookie", cookie)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let (s, j, _) = request(env, req).await;
    (s, j)
}

async fn authed_delete(env: &TestEnv, path: &str, cookie: &str) -> (StatusCode, Value) {
    let req = Request::builder()
        .method("DELETE")
        .uri(path)
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    let (s, j, _) = request(env, req).await;
    (s, j)
}

// ----------------------------- magic-link -----------------------------

#[sqlx::test]
async fn magic_link_request_for_known_email_returns_dev_token(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_known", "user@example.com", "dev").await;
    let env = env(pool);

    let (status, json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/request",
        json!({"email": "user@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body = {json}");
    assert_eq!(json["sent"], true);
    assert!(
        json["dev_token"].is_string(),
        "dev_token must be returned when RESEND_API_KEY is unset"
    );
}

#[sqlx::test]
async fn magic_link_request_for_unknown_email_silent_200(pool: PgPool) {
    let env = env(pool);
    let (status, json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/request",
        json!({"email": "nobody@example.com"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["sent"], true);
    assert!(
        json.get("dev_token").is_none() || json["dev_token"].is_null(),
        "no token must leak for unknown email (privacy): {json}"
    );
}

#[sqlx::test]
async fn magic_link_request_rejects_malformed_email(pool: PgPool) {
    let env = env(pool);
    let (status, json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/request",
        json!({"email": "not-an-email"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "bad_request");
}

#[sqlx::test]
async fn magic_link_verify_sets_session_cookie(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_v", "v@example.com", "dev").await;
    let env = env(pool);

    let (_, request_json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/request",
        json!({"email": "v@example.com"}),
    )
    .await;
    let token = request_json["dev_token"].as_str().unwrap().to_string();

    let (status, json, cookies) = post_json(
        &env,
        "/v1/customer/auth/magic-link/verify",
        json!({"token": token}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body = {json}");
    assert_eq!(json["stripe_customer_id"], "cus_v");
    assert_eq!(json["email"], "v@example.com");

    assert!(
        cookies.iter().any(|c| c.starts_with("aex_session=")
            && c.contains("HttpOnly")
            && c.contains("Secure")),
        "Set-Cookie must include aex_session with HttpOnly+Secure: {cookies:?}"
    );
}

#[sqlx::test]
async fn magic_link_verify_is_single_use(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_su", "su@example.com", "dev").await;
    let env = env(pool);

    let (_, request_json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/request",
        json!({"email": "su@example.com"}),
    )
    .await;
    let token = request_json["dev_token"].as_str().unwrap().to_string();

    // First verify succeeds.
    let (s1, _, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/verify",
        json!({"token": token}),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    // Second verify fails — single-use invariant.
    let (s2, j2, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/verify",
        json!({"token": token}),
    )
    .await;
    assert_eq!(s2, StatusCode::UNAUTHORIZED);
    assert_eq!(j2["code"], "unauthorized");
    assert!(j2["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("magic-link-invalid.md"));
}

#[sqlx::test]
async fn magic_link_verify_rejects_unknown_token(pool: PgPool) {
    let env = env(pool);
    let (status, json, _) = post_json(
        &env,
        "/v1/customer/auth/magic-link/verify",
        json!({"token": "deadbeef"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("magic-link-invalid.md"));
}

// ----------------------------- session middleware -----------------------------

#[sqlx::test]
async fn whoami_requires_session(pool: PgPool) {
    let env = env(pool);
    let req = Request::builder()
        .method("GET")
        .uri("/v1/customer/auth/whoami")
        .body(Body::empty())
        .unwrap();
    let (status, json, _) = request(&env, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("session-invalid.md"));
}

#[sqlx::test]
async fn whoami_with_valid_session(pool: PgPool) {
    let env = env(pool);
    let cookie = issue_session_cookie("cus_who");
    let (status, json) = authed_get(&env, "/v1/customer/auth/whoami", &cookie).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["stripe_customer_id"], "cus_who");
}

#[sqlx::test]
async fn logout_returns_clear_cookie(pool: PgPool) {
    let env = env(pool);
    let cookie = issue_session_cookie("cus_logout");

    let req = Request::builder()
        .method("POST")
        .uri("/v1/customer/auth/logout")
        .header("cookie", &cookie)
        .body(Body::empty())
        .unwrap();
    let (status, json, cookies) = request(&env, req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["logged_out"], true);
    assert!(
        cookies
            .iter()
            .any(|c| c.contains("aex_session=") && c.contains("Max-Age=0")),
        "logout must Set-Cookie with Max-Age=0: {cookies:?}"
    );
}

// ----------------------------- customer api-keys -----------------------------

#[sqlx::test]
async fn customer_can_mint_api_key_when_active(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_mint", "m@example.com", "dev").await;
    let env = env(pool);
    let cookie = issue_session_cookie("cus_mint");

    let (status, json) = authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie,
        json!({"name": "my laptop"}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "body = {json}");
    assert_eq!(json["customer_id"], "cus_mint");
    assert_eq!(json["tier"], "dev");
    assert_eq!(json["name"], "my laptop");
    let plaintext = json["api_key"].as_str().unwrap();
    assert!(plaintext.starts_with("aex_live_"));
}

#[sqlx::test]
async fn customer_mint_rejected_without_subscription(pool: PgPool) {
    seed_customer_only(&pool, "cus_nosub", "ns@example.com").await;
    let env = env(pool);
    let cookie = issue_session_cookie("cus_nosub");

    let (status, json) = authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie,
        json!({"name": "broken"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("no-active-subscription.md"));
}

#[sqlx::test]
async fn customer_lists_only_own_keys(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_list_a", "a@example.com", "dev").await;
    seed_customer_with_subscription(&pool, "cus_list_b", "b@example.com", "team").await;
    let env = env(pool);
    let cookie_a = issue_session_cookie("cus_list_a");
    let cookie_b = issue_session_cookie("cus_list_b");

    // A mints 2 keys, B mints 1 key.
    authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie_a,
        json!({"name": "a1"}),
    )
    .await;
    authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie_a,
        json!({"name": "a2"}),
    )
    .await;
    authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie_b,
        json!({"name": "b1"}),
    )
    .await;

    let (status, json) = authed_get(&env, "/v1/customer/api-keys", &cookie_a).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["count"], 2);
    for key in json["keys"].as_array().unwrap() {
        assert_eq!(key["customer_id"], "cus_list_a", "leakage from B");
    }
}

#[sqlx::test]
async fn customer_can_revoke_own_key_but_not_someone_elses(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_owner", "owner@example.com", "dev").await;
    seed_customer_with_subscription(&pool, "cus_attacker", "attacker@example.com", "dev").await;
    let env = env(pool);
    let cookie_owner = issue_session_cookie("cus_owner");
    let cookie_attacker = issue_session_cookie("cus_attacker");

    let (_, owner_key) = authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie_owner,
        json!({"name": "owner key"}),
    )
    .await;
    let key_id = owner_key["id"].as_str().unwrap().to_string();

    // Attacker tries to revoke owner's key — must 404, NOT 403
    // (no information leak about ownership).
    let (status, _) = authed_delete(
        &env,
        &format!("/v1/customer/api-keys/{key_id}"),
        &cookie_attacker,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Owner can revoke their own key.
    let (status, json) = authed_delete(
        &env,
        &format!("/v1/customer/api-keys/{key_id}"),
        &cookie_owner,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json["revoked_at"].is_string());
}

#[sqlx::test]
async fn customer_cannot_mint_above_max_keys(pool: PgPool) {
    seed_customer_with_subscription(&pool, "cus_cap", "cap@example.com", "dev").await;
    let env = env(pool);
    let cookie = issue_session_cookie("cus_cap");

    // 10 successful mints.
    for i in 0..10 {
        let (status, _) = authed_post(
            &env,
            "/v1/customer/api-keys",
            &cookie,
            json!({"name": format!("k{i}")}),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "mint #{i} must succeed");
    }

    // 11th mint must 409 with the cap runbook.
    let (status, json) = authed_post(
        &env,
        "/v1/customer/api-keys",
        &cookie,
        json!({"name": "overflow"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("max-keys-reached.md"));
}
