//! Integration tests for the admin bearer-token gate (Sprint 4 PR 1).
//!
//! Four scenarios:
//!
//! | Scenario                         | Status | Body code        |
//! |----------------------------------|--------|------------------|
//! | Missing AEX_ADMIN_TOKEN on server| 503    | `admin_disabled` |
//! | No Authorization header          | 401    | `unauthorized`   |
//! | Authorization with wrong token   | 403    | `forbidden`      |
//! | Authorization with correct token | 200    | (whoami body)    |
//!
//! Each scenario builds a fresh `TestEnv` so the admin_token state is
//! isolated. The Postgres pool comes from `#[sqlx::test]` even though
//! the admin middleware doesn't touch the DB — keeps the harness
//! parallel with the rest of the CP test suite.

mod common;

use axum::http::StatusCode;
use sqlx::PgPool;

use aex_policy::TierName;
use common::TestEnv;

const VALID_TOKEN: &str = "aabbccddeeff00112233445566778899";
const WRONG_TOKEN: &str = "ffeeddccbbaa99887766554433221100";

#[sqlx::test]
async fn without_admin_token_configured_returns_503(pool: PgPool) {
    // Default TestEnv has no admin_token → middleware answers 503.
    let env = TestEnv::new(pool);
    let (status, body) = env
        .get_with_auth("/v1/admin/whoami", &format!("Bearer {VALID_TOKEN}"))
        .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "admin_disabled");
    assert!(body["message"]
        .as_str()
        .unwrap_or("")
        .contains("AEX_ADMIN_TOKEN"));
}

#[sqlx::test]
async fn missing_authorization_header_returns_401(pool: PgPool) {
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    let (status, body) = env.get("/v1/admin/whoami").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "unauthorized");
}

#[sqlx::test]
async fn malformed_authorization_header_returns_401(pool: PgPool) {
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    // Not a "Bearer <token>" shape → 401.
    let (status, _) = env
        .get_with_auth("/v1/admin/whoami", "Basic user:pass")
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[sqlx::test]
async fn bearer_with_short_token_returns_401(pool: PgPool) {
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    let (status, _) = env
        .get_with_auth("/v1/admin/whoami", "Bearer deadbeef")
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "sub-32-char bearer tokens are rejected early"
    );
}

#[sqlx::test]
async fn wrong_admin_token_returns_403(pool: PgPool) {
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    let (status, body) = env
        .get_with_auth("/v1/admin/whoami", &format!("Bearer {WRONG_TOKEN}"))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "forbidden");
}

#[sqlx::test]
async fn correct_admin_token_reaches_whoami(pool: PgPool) {
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    let (status, body) = env
        .get_with_auth("/v1/admin/whoami", &format!("Bearer {VALID_TOKEN}"))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], true);
    assert_eq!(body["service"], "aex-control-plane");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[sqlx::test]
async fn non_admin_paths_work_without_token(pool: PgPool) {
    // The admin middleware is scoped to /v1/admin/* — unrelated
    // endpoints must still be reachable without a token.
    let env =
        TestEnv::with_state_override(pool, TierName::Dev, |s| s.with_admin_token(VALID_TOKEN));
    let (status, body) = env.get("/healthz").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}
