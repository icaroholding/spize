//! Integration tests for `/webhooks/stripe` (Sprint 4 PR 6).
//!
//! Covers end-to-end flow of a Stripe webhook event:
//!
//! - Positive paths: `customer.subscription.created` / `.updated`
//!   upsert a row into `subscriptions` with the right tier.
//! - `customer.subscription.deleted` flips the subscription status
//!   to `canceled` AND revokes every live api_key for that
//!   customer in the same transaction.
//! - Negative paths: missing/invalid/stale signatures → 401; bad
//!   JSON → 400; Stripe disabled → 503; unknown price → row not
//!   written (but still 200 for Stripe's retry cooperation).
//! - Idempotency: replaying the same `event.id` is a no-op.

mod common;

use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use sqlx::PgPool;
use tower::ServiceExt;

use aex_control_plane::{clock::FrozenClock, config::StripeConfig};
use aex_policy::TierName;
use common::TestEnv;

const ADMIN_TOKEN: &str = "aabbccddeeff00112233445566778899";
const WEBHOOK_SECRET: &str = "whsec_test_0123456789abcdef";
const PRICE_DEV: &str = "price_dev_abc";
const PRICE_TEAM: &str = "price_team_xyz";
const FROZEN_NOW: i64 = 1_700_000_000;

type HmacSha256 = Hmac<Sha256>;

// ------------------------- helpers -------------------------

/// Build a TestEnv with admin token + Stripe config + a frozen
/// clock at `FROZEN_NOW` so webhook signatures we build at
/// `FROZEN_NOW` verify without clock skew.
fn env(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| {
        s.with_admin_token(ADMIN_TOKEN)
            .with_stripe(StripeConfig {
                webhook_secret: Some(WEBHOOK_SECRET.into()),
                price_dev: Some(PRICE_DEV.into()),
                price_team: Some(PRICE_TEAM.into()),
            })
            .with_clock(Arc::new(FrozenClock::new(FROZEN_NOW)))
    })
}

/// TestEnv without Stripe config — used to prove the 503 guard.
fn env_without_stripe(pool: PgPool) -> TestEnv {
    TestEnv::with_state_override(pool, TierName::Dev, |s| {
        s.with_admin_token(ADMIN_TOKEN)
            .with_clock(Arc::new(FrozenClock::new(FROZEN_NOW)))
    })
}

/// Compute `t=<t>,v1=<hmac>` the way Stripe does.
fn sign(secret: &str, t: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let sig = hex::encode(mac.finalize().into_bytes());
    format!("t={t},v1={sig}")
}

/// Build a subscription event body mirroring Stripe's real envelope
/// shape (simplified to just the fields our handler reads).
fn subscription_event(
    event_id: &str,
    event_type: &str,
    customer_id: &str,
    subscription_id: &str,
    price_id: &str,
    status: &str,
) -> Value {
    json!({
        "id": event_id,
        "type": event_type,
        "data": {
            "object": {
                "id": subscription_id,
                "customer": customer_id,
                "status": status,
                "items": {
                    "data": [
                        { "price": { "id": price_id } }
                    ]
                }
            }
        }
    })
}

async fn post_webhook(
    env: &TestEnv,
    body: &[u8],
    signature_header: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri("/webhooks/stripe")
        .header("content-type", "application/json");
    if let Some(h) = signature_header {
        req = req.header("stripe-signature", h);
    }
    let req = req.body(Body::from(body.to_vec())).unwrap();
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

async fn fetch_subscription_row(pool: &PgPool, customer_id: &str) -> Option<(String, String)> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT tier, status FROM subscriptions WHERE stripe_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(pool)
    .await
    .unwrap()
}

async fn count_active_keys(pool: &PgPool, customer_id: &str) -> i64 {
    sqlx::query_as::<_, (i64,)>(
        "SELECT COUNT(*) FROM api_keys WHERE customer_id = $1 AND revoked_at IS NULL",
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await
    .unwrap()
    .0
}

/// Mint an API key via the admin surface so we have something to
/// revoke in the subscription.deleted tests.
async fn mint_admin_key(env: &TestEnv, customer_id: &str, tier: &str) -> String {
    let bearer = format!("Bearer {ADMIN_TOKEN}");
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/api-keys")
        .header("authorization", &bearer)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({
                "customer_id": customer_id,
                "name": "pre-cancel key",
                "tier": tier,
            }))
            .unwrap(),
        ))
        .unwrap();
    let resp = env.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    body["id"].as_str().unwrap().to_string()
}

// ------------------------- positive paths -------------------------

#[sqlx::test]
async fn subscription_created_dev_upserts_row(pool: PgPool) {
    let env = env(pool.clone());
    let body = subscription_event(
        "evt_sub_created_1",
        "customer.subscription.created",
        "cus_new",
        "sub_001",
        PRICE_DEV,
        "active",
    );
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &body_bytes);

    let (status, json) = post_webhook(&env, &body_bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::OK, "body = {json}");
    assert_eq!(json["received"], true);
    assert_eq!(json["outcome"], "upserted");

    let row = fetch_subscription_row(&pool, "cus_new").await.unwrap();
    assert_eq!(row.0, "dev");
    assert_eq!(row.1, "active");
}

#[sqlx::test]
async fn subscription_created_team_tier_row(pool: PgPool) {
    let env = env(pool.clone());
    let body = subscription_event(
        "evt_team_1",
        "customer.subscription.created",
        "cus_team",
        "sub_team",
        PRICE_TEAM,
        "active",
    );
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &body_bytes);

    let (status, _) = post_webhook(&env, &body_bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::OK);

    let row = fetch_subscription_row(&pool, "cus_team").await.unwrap();
    assert_eq!(row.0, "team");
}

#[sqlx::test]
async fn subscription_updated_changes_tier(pool: PgPool) {
    let env = env(pool.clone());
    // First: customer on dev.
    for (id, price) in [("evt_up_a", PRICE_DEV), ("evt_up_b", PRICE_TEAM)] {
        let body = subscription_event(
            id,
            "customer.subscription.updated",
            "cus_upgrader",
            "sub_up",
            price,
            "active",
        );
        let bytes = serde_json::to_vec(&body).unwrap();
        let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
        let (s, _) = post_webhook(&env, &bytes, Some(&sig)).await;
        assert_eq!(s, StatusCode::OK);
    }
    let row = fetch_subscription_row(&pool, "cus_upgrader").await.unwrap();
    assert_eq!(
        row.0, "team",
        "second upsert must overwrite tier, not duplicate row"
    );
}

#[sqlx::test]
async fn subscription_deleted_revokes_all_keys(pool: PgPool) {
    let env = env(pool.clone());

    // Seed: customer has 2 active api_keys and an active subscription.
    mint_admin_key(&env, "cus_cancel", "dev").await;
    mint_admin_key(&env, "cus_cancel", "dev").await;
    let created_body = subscription_event(
        "evt_seed",
        "customer.subscription.created",
        "cus_cancel",
        "sub_cancel",
        PRICE_DEV,
        "active",
    );
    let bytes = serde_json::to_vec(&created_body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
    let (s, _) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(count_active_keys(&pool, "cus_cancel").await, 2);

    // Now delete the subscription.
    let deleted = json!({
        "id": "evt_del_1",
        "type": "customer.subscription.deleted",
        "data": { "object": { "id": "sub_cancel", "customer": "cus_cancel", "status": "canceled" } }
    });
    let bytes = serde_json::to_vec(&deleted).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["outcome"], "revoked");
    assert_eq!(
        count_active_keys(&pool, "cus_cancel").await,
        0,
        "all api_keys must be revoked on subscription.deleted"
    );
    let row = fetch_subscription_row(&pool, "cus_cancel").await.unwrap();
    assert_eq!(row.1, "canceled");
}

#[sqlx::test]
async fn non_active_status_upsert_revokes_keys(pool: PgPool) {
    // Stripe can tell us a subscription has moved to `canceled` via
    // an updated event (not just deleted). Keys must die the same way.
    let env = env(pool.clone());
    mint_admin_key(&env, "cus_churn", "dev").await;

    let body = subscription_event(
        "evt_churn",
        "customer.subscription.updated",
        "cus_churn",
        "sub_churn",
        PRICE_DEV,
        "canceled",
    );
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["outcome"], "upserted_and_revoked");
    assert_eq!(count_active_keys(&pool, "cus_churn").await, 0);
}

// ------------------------- idempotency -------------------------

#[sqlx::test]
async fn duplicate_event_id_is_idempotent(pool: PgPool) {
    let env = env(pool.clone());
    let body = subscription_event(
        "evt_dup",
        "customer.subscription.created",
        "cus_idem",
        "sub_idem",
        PRICE_DEV,
        "active",
    );
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);

    let (s1, j1) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(j1["outcome"], "upserted");

    // Replay: same id, same body, same signature.
    let (s2, j2) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(s2, StatusCode::OK, "replay must ack with 200 for stripe");
    assert_eq!(j2["outcome"], "duplicate");
}

// ------------------------- negative paths -------------------------

#[sqlx::test]
async fn missing_signature_returns_401(pool: PgPool) {
    let env = env(pool);
    let body =
        json!({"id": "evt_x", "type": "customer.subscription.created", "data":{"object":{}}});
    let bytes = serde_json::to_vec(&body).unwrap();
    let (status, json) = post_webhook(&env, &bytes, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "stripe_signature_missing");
    assert!(json["runbook_url"]
        .as_str()
        .unwrap()
        .ends_with("stripe-signature-missing.md"));
}

#[sqlx::test]
async fn bad_signature_returns_401(pool: PgPool) {
    let env = env(pool);
    let body = json!({"id":"evt_bad","type":"customer.subscription.created","data":{"object":{}}});
    let bytes = serde_json::to_vec(&body).unwrap();
    // Signed with the WRONG secret.
    let sig = sign("whsec_WRONG", FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "stripe_signature_invalid");
}

#[sqlx::test]
async fn stale_timestamp_returns_401(pool: PgPool) {
    let env = env(pool);
    let body =
        json!({"id":"evt_stale","type":"customer.subscription.created","data":{"object":{}}});
    let bytes = serde_json::to_vec(&body).unwrap();
    // Signed at a time 10 minutes in the past relative to the
    // clock — outside the 300s tolerance.
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW - 600, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(json["code"], "stripe_signature_invalid");
}

#[sqlx::test]
async fn malformed_event_body_returns_400(pool: PgPool) {
    let env = env(pool);
    // Valid signature but body is not JSON.
    let bytes = b"this is not json";
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, bytes);
    let (status, json) = post_webhook(&env, bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(json["code"], "stripe_event_malformed");
}

#[sqlx::test]
async fn stripe_disabled_returns_503(pool: PgPool) {
    let env = env_without_stripe(pool);
    let body = json!({"id":"evt","type":"customer.subscription.created","data":{"object":{}}});
    let bytes = serde_json::to_vec(&body).unwrap();
    // Signature doesn't matter — config guard fires first.
    let sig = sign("anything", FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(json["code"], "stripe_disabled");
}

#[sqlx::test]
async fn unknown_price_id_does_not_write_row(pool: PgPool) {
    let env = env(pool.clone());
    let body = subscription_event(
        "evt_unknown_price",
        "customer.subscription.created",
        "cus_unknown_price",
        "sub_u",
        "price_unmapped_123", // not dev, not team
        "active",
    );
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;

    assert_eq!(status, StatusCode::OK, "still 200 — Stripe must not retry");
    assert_eq!(json["outcome"], "skipped_unknown_price");
    assert!(
        fetch_subscription_row(&pool, "cus_unknown_price")
            .await
            .is_none(),
        "no subscription row should be written for an unknown price"
    );
}

#[sqlx::test]
async fn unhandled_event_type_ack_200(pool: PgPool) {
    // Future-proof: Stripe adds new event types; we must ack with
    // 200 to stop retries rather than 400-ing the unknown shape.
    let env = env(pool);
    let body = json!({
        "id": "evt_price_created",
        "type": "price.created",
        "data": { "object": { "id": "price_xyz" } }
    });
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign(WEBHOOK_SECRET, FROZEN_NOW, &bytes);
    let (status, json) = post_webhook(&env, &bytes, Some(&sig)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["outcome"], "ignored");
}
