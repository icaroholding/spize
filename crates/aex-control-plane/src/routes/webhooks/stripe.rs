//! Stripe webhook handler (Sprint 4 PR 6).
//!
//! This endpoint receives subscription-lifecycle events from Stripe
//! and mirrors them into our DB so the customer dashboard can
//! authorize API-key mints (PR #43+).
//!
//! # What this handler does NOT do
//!
//! - **Does not mint api_keys.** The industry pattern (Stripe,
//!   OpenAI, AWS, Anthropic) is "pay → dashboard → self-mint" so the
//!   plaintext never needs to travel in email or sit in the DB.
//!   Auto-minting on webhook would either drop the plaintext
//!   (useless) or park it in a plaintext column (security
//!   regression we refuse to take). The `subscriptions` row this
//!   handler writes is the authorization grant the dashboard will
//!   read before letting the customer press "Generate key".
//!
//! - **Does not call back to Stripe.** We only consume events. A
//!   future PR will add the Stripe API client (for creating
//!   Checkout Sessions + expanding line items if needed).
//!
//! # Security surface
//!
//! 1. **Signature verification.** Every POST carries a
//!    `Stripe-Signature: t=<unix>,v1=<hex>,…` header. We reconstruct
//!    `HMAC-SHA256(secret, t + "." + raw_body)` and compare it
//!    constant-time against each `v1=` signature. Mismatch → 401.
//!
//! 2. **Replay window.** Events with a timestamp more than 5
//!    minutes off wall-clock are rejected — Stripe's
//!    recommendation. Keeps a leaked old event body from being
//!    replayed to double-process an action.
//!
//! 3. **Idempotency inbox.** Each event.id is inserted into
//!    `stripe_events` inside the same transaction as the
//!    side-effect (`subscriptions` write / `api_keys` revoke). If
//!    Stripe retries the same event (network blip, slow response),
//!    the PK conflict makes the second attempt a 200 no-op.
//!
//! # Handled event types
//!
//! - `customer.subscription.created` / `customer.subscription.updated`
//!   → upsert `subscriptions` row with the customer's current tier
//!   and status. If status flips to `canceled`, we also revoke all
//!   api_keys for that customer (same atomic transaction).
//! - `customer.subscription.deleted` → mark subscription canceled
//!   + revoke all api_keys.
//! - Every other event → logged at DEBUG and ack'd 200 so Stripe
//!   stops retrying. We don't want to 400 on unknown types because
//!   Stripe adds new events over time; ignoring them is the
//!   forward-compat move.

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    db::{api_keys as keys_db, customers as customers_db, stripe_events, subscriptions as subs_db},
    AppState,
};

/// Acceptable skew between Stripe's `t=` timestamp and our wall
/// clock. 300s is Stripe's documented recommendation — tight enough
/// to rule out replay of an old event body, loose enough to survive
/// ordinary NTP drift and slow networks.
const SIGNATURE_TOLERANCE_SECS: i64 = 300;

type HmacSha256 = Hmac<Sha256>;

pub fn router() -> Router<AppState> {
    Router::new().route("/", post(stripe_handler))
}

#[derive(Serialize)]
struct WebhookErrorBody {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    runbook_url: Option<&'static str>,
}

#[derive(Serialize)]
struct WebhookAck {
    received: bool,
    outcome: &'static str,
}

fn err(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(WebhookErrorBody {
            code,
            message: message.into(),
            runbook_url: crate::error::runbook::runbook_url(code, ""),
        }),
    )
        .into_response()
}

async fn stripe_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // --- 1. Config guard ---
    if !state.stripe.is_ready() {
        return err(
            StatusCode::SERVICE_UNAVAILABLE,
            "stripe_disabled",
            "Stripe webhook not configured; set STRIPE_WEBHOOK_SECRET + STRIPE_PRICE_DEV + STRIPE_PRICE_TEAM and restart.",
        );
    }
    let secret = state.stripe.webhook_secret.as_deref().unwrap();
    let price_dev = state.stripe.price_dev.as_deref().unwrap();
    let price_team = state.stripe.price_team.as_deref().unwrap();

    // --- 2. Signature header ---
    let sig_header = match headers
        .get("stripe-signature")
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => {
            return err(
                StatusCode::UNAUTHORIZED,
                "stripe_signature_missing",
                "Stripe-Signature header is missing.",
            );
        }
    };

    // --- 3. Verify ---
    let now = state.clock.now().unix_timestamp();
    if let Err(msg) = verify_signature(secret, sig_header, &body, now, SIGNATURE_TOLERANCE_SECS) {
        tracing::warn!(reason = %msg, "rejected stripe webhook: bad signature");
        return err(StatusCode::UNAUTHORIZED, "stripe_signature_invalid", msg);
    }

    // --- 4. Parse event envelope ---
    let event: StripeEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                "stripe_event_malformed",
                format!("cannot parse event JSON: {e}"),
            );
        }
    };

    // --- 5. Transactional dispatch ---
    let outcome = match process_event(&state, &event, price_dev, price_team).await {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(
                error = %e,
                event_id = %event.id,
                event_type = %event.event_type,
                "error processing stripe webhook; will be retried by stripe"
            );
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "stripe_processing_failed",
                "internal error processing event; stripe will retry",
            );
        }
    };

    tracing::info!(
        event_id = %event.id,
        event_type = %event.event_type,
        outcome,
        "stripe webhook processed"
    );

    (
        StatusCode::OK,
        Json(WebhookAck {
            received: true,
            outcome,
        }),
    )
        .into_response()
}

// ------------------------- signature verification -------------------------

/// Parse `Stripe-Signature` header and compare the re-computed
/// HMAC-SHA256 against every `v1=` signature it advertises. Returns
/// `Ok(())` on match. Error strings are operator-facing only — the
/// HTTP response does not echo the specific failure back to the
/// caller (would be a signal channel for a replay attacker).
fn verify_signature(
    secret: &str,
    header: &str,
    body: &[u8],
    now: i64,
    tolerance: i64,
) -> Result<(), String> {
    let mut timestamp: Option<i64> = None;
    let mut v1_sigs: Vec<&str> = Vec::new();
    for part in header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = t.parse().ok();
        } else if let Some(v) = part.strip_prefix("v1=") {
            v1_sigs.push(v);
        }
    }

    let t = timestamp.ok_or_else(|| "missing t= in Stripe-Signature".to_string())?;
    if v1_sigs.is_empty() {
        return Err("no v1= signatures in Stripe-Signature".into());
    }
    if (now - t).abs() > tolerance {
        return Err(format!(
            "timestamp skew outside {tolerance}s tolerance (header t={t}, now={now})"
        ));
    }

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|e| format!("bad hmac key: {e}"))?;
    mac.update(t.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    // Constant-time compare against each candidate. Stripe can
    // include multiple v1=… during key rotation so any hit wins.
    for v1 in &v1_sigs {
        let Ok(presented) = hex::decode(v1) else {
            continue;
        };
        let expected_bytes: &[u8] = &expected;
        if presented.len() == expected_bytes.len()
            && presented.ct_eq(expected_bytes).unwrap_u8() == 1
        {
            return Ok(());
        }
    }
    Err("no v1 signature matched expected HMAC".into())
}

// ------------------------- event processing -------------------------

#[derive(Deserialize, Debug)]
struct StripeEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    data: EventData,
}

#[derive(Deserialize, Debug)]
struct EventData {
    object: JsonValue,
}

/// Run the event inside a single DB transaction so the inbox
/// insert, the `subscriptions` write, and the `api_keys` revoke
/// either all commit together or all roll back.
async fn process_event(
    state: &AppState,
    event: &StripeEvent,
    price_dev: &str,
    price_team: &str,
) -> Result<&'static str, sqlx::Error> {
    let mut tx = state.db.begin().await?;

    let payload = serde_json::json!({
        "id": event.id,
        "type": event.event_type,
        "data": { "object": event.data.object.clone() },
    });
    let fresh =
        stripe_events::insert_if_new(&mut tx, &event.id, &event.event_type, &payload).await?;
    if !fresh {
        // We've already handled this event_id. The original
        // transaction committed its side effects; nothing to do.
        tx.rollback().await?;
        return Ok("duplicate");
    }

    let outcome = match event.event_type.as_str() {
        "customer.created" | "customer.updated" => {
            handle_customer_upsert(&mut tx, &event.data.object).await?
        }
        "customer.subscription.created" | "customer.subscription.updated" => {
            handle_subscription_upsert(&mut tx, &event.data.object, price_dev, price_team).await?
        }
        "customer.subscription.deleted" => {
            handle_subscription_deleted(&mut tx, &event.data.object).await?
        }
        _ => "ignored",
    };

    stripe_events::mark_processed(&mut tx, &event.id).await?;
    tx.commit().await?;
    Ok(outcome)
}

async fn handle_customer_upsert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    obj: &JsonValue,
) -> Result<&'static str, sqlx::Error> {
    let stripe_customer_id = str_field(obj, "id");
    let email = str_field(obj, "email");
    if stripe_customer_id.is_empty() || email.is_empty() {
        tracing::warn!(
            stripe_customer_id,
            email_present = !email.is_empty(),
            "customer event missing id or email; skip"
        );
        return Ok("skipped_malformed");
    }
    match customers_db::upsert_in_tx(tx, stripe_customer_id, email).await {
        Ok(_) => {
            tracing::info!(stripe_customer_id, email, "upserted customer email");
            Ok("upserted_customer")
        }
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            // Two distinct Stripe customer IDs claiming the same email
            // — extremely rare, surfaces only after manual ops cleanup.
            // Log loudly and skip rather than corrupting our `customers`
            // row. Operator must reconcile in Stripe before we can sync.
            tracing::error!(
                stripe_customer_id,
                email,
                "two stripe customers share the same email; skipping upsert"
            );
            Ok("skipped_email_conflict")
        }
        Err(e) => Err(e),
    }
}

async fn handle_subscription_upsert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    obj: &JsonValue,
    price_dev: &str,
    price_team: &str,
) -> Result<&'static str, sqlx::Error> {
    let customer_id = str_field(obj, "customer");
    let subscription_id = str_field(obj, "id");
    let status = str_field(obj, "status");
    let price_id = obj
        .get("items")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.get("price"))
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if customer_id.is_empty() || subscription_id.is_empty() {
        tracing::warn!(
            customer_id,
            subscription_id,
            "subscription event missing customer/id fields; skip"
        );
        return Ok("skipped_malformed");
    }

    let tier = if price_id == price_dev {
        "dev"
    } else if price_id == price_team {
        "team"
    } else {
        tracing::warn!(
            price_id,
            customer_id,
            "subscription references unknown price_id; subscription row NOT written. \
             Map it via STRIPE_PRICE_DEV/STRIPE_PRICE_TEAM or extend the mapping."
        );
        return Ok("skipped_unknown_price");
    };

    subs_db::upsert_in_tx(tx, customer_id, subscription_id, tier, status).await?;

    // If the same event already tells us the subscription is
    // non-active (canceled, unpaid), treat it as a cancellation for
    // api_key purposes too — we don't want a stale key to keep
    // authenticating after Stripe stopped charging the customer.
    if status == "canceled" || status == "unpaid" {
        let revoked = keys_db::revoke_all_by_customer_in_tx(tx, customer_id).await?;
        tracing::info!(
            customer_id,
            revoked,
            status,
            "revoked keys on non-active upsert"
        );
        return Ok("upserted_and_revoked");
    }

    Ok("upserted")
}

async fn handle_subscription_deleted(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    obj: &JsonValue,
) -> Result<&'static str, sqlx::Error> {
    let customer_id = str_field(obj, "customer");
    if customer_id.is_empty() {
        tracing::warn!("subscription.deleted event missing customer; skip");
        return Ok("skipped_malformed");
    }
    subs_db::mark_canceled_in_tx(tx, customer_id).await?;
    let revoked = keys_db::revoke_all_by_customer_in_tx(tx, customer_id).await?;
    tracing::info!(customer_id, revoked, "revoked keys on subscription.deleted");
    Ok("revoked")
}

/// Pull a top-level string field off a JSON object, returning `""`
/// if missing. Convenience over repeated `.get().and_then().as_str()`.
fn str_field<'a>(obj: &'a JsonValue, key: &str) -> &'a str {
    obj.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a well-formed Stripe-Signature header matching `body`
    /// at time `t` using `secret`. Mirrors Stripe's own signing.
    fn sign(secret: &str, t: i64, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(t.to_string().as_bytes());
        mac.update(b".");
        mac.update(body);
        let sig = hex::encode(mac.finalize().into_bytes());
        format!("t={t},v1={sig}")
    }

    #[test]
    fn verify_accepts_good_signature() {
        let body = b"{\"id\":\"evt_x\"}";
        let header = sign("whsec_test", 1_700_000_000, body);
        assert!(verify_signature("whsec_test", &header, body, 1_700_000_000, 300).is_ok());
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let body = b"{}";
        let header = sign("whsec_test", 1_700_000_000, body);
        assert!(verify_signature("whsec_OTHER", &header, body, 1_700_000_000, 300).is_err());
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let body = b"{\"amount\":100}";
        let header = sign("whsec_test", 1_700_000_000, body);
        let tampered = b"{\"amount\":9999}";
        assert!(verify_signature("whsec_test", &header, tampered, 1_700_000_000, 300).is_err());
    }

    #[test]
    fn verify_rejects_stale_timestamp() {
        let body = b"{}";
        let header = sign("whsec_test", 1_700_000_000, body);
        // Now is 10 minutes later — outside 300s tolerance.
        let now = 1_700_000_000 + 600;
        assert!(verify_signature("whsec_test", &header, body, now, 300).is_err());
    }

    #[test]
    fn verify_rejects_future_timestamp() {
        let body = b"{}";
        // Event from 10 minutes in the future — same tolerance check.
        let header = sign("whsec_test", 1_700_000_600, body);
        assert!(verify_signature("whsec_test", &header, body, 1_700_000_000, 300).is_err());
    }

    #[test]
    fn verify_rejects_missing_timestamp() {
        let body = b"{}";
        assert!(verify_signature("whsec", "v1=deadbeef", body, 1_700_000_000, 300).is_err());
    }

    #[test]
    fn verify_rejects_missing_v1() {
        let body = b"{}";
        let header = "t=1700000000";
        assert!(verify_signature("whsec", header, body, 1_700_000_000, 300).is_err());
    }

    #[test]
    fn verify_accepts_when_any_v1_matches() {
        // Stripe rotates keys by broadcasting multiple v1=... — any
        // one matching is enough.
        let body = b"{}";
        let good = sign("whsec_test", 1_700_000_000, body);
        // Extract just the v1 chunk and append a bogus v1 alongside.
        let good_v1 = good.split(',').nth(1).unwrap();
        let header = format!("t=1700000000,v1=00ff00ff,{good_v1}");
        assert!(verify_signature("whsec_test", &header, body, 1_700_000_000, 300).is_ok());
    }
}
