//! Customer-scoped API key management (Sprint 4 PR 7).
//!
//! Three endpoints, all behind the session middleware so the
//! "current customer" is `Extension<CustomerSession>::sub`:
//!
//! - `POST /v1/customer/api-keys`   — mint a key for the caller
//! - `GET  /v1/customer/api-keys`   — list the caller's own keys
//! - `DELETE /v1/customer/api-keys/:id` — revoke a key the caller
//!   owns. A foreign key id returns 404 (don't leak existence).
//!
//! Mint requires an active subscription (`subscriptions.status =
//! 'active'` or `'trialing'`). Otherwise 403 with a runbook URL
//! pointing at `/customer-no-active-subscription.md`.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, post},
    Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    db::api_keys as keys_db, error::ApiError, routes::admin::ApiKeyView, session::CustomerSession,
    AppState,
};

/// Soft cap on simultaneous active keys per customer. Matches what
/// most SaaS dashboards default to (e.g. Stripe shows 10 in the
/// dashboard) — generous for legitimate needs, low enough to limit
/// blast radius if the dashboard is compromised.
const MAX_ACTIVE_KEYS_PER_CUSTOMER: i64 = 10;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/api-keys", post(mint).get(list))
        .route("/api-keys/:id", delete(revoke))
}

#[derive(Deserialize)]
pub struct MintBody {
    pub name: String,
}

#[derive(Serialize)]
pub struct MintResponse {
    #[serde(flatten)]
    pub key: ApiKeyView,
    /// THE plaintext key. Shown exactly once, in this response —
    /// the dashboard renders it in a copy-once modal and the server
    /// has no way to retrieve it again.
    pub api_key: String,
}

async fn mint(
    State(state): State<AppState>,
    Extension(session): Extension<CustomerSession>,
    Json(req): Json<MintBody>,
) -> Result<(StatusCode, Json<MintResponse>), ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is empty".into()));
    }

    let sub = fetch_active_subscription(&state, &session.sub).await?;

    let active_keys = count_active_keys_for_customer(&state.db, &session.sub).await? as i64;
    if active_keys >= MAX_ACTIVE_KEYS_PER_CUSTOMER {
        return Err(ApiError::Conflict(format!(
            "max {MAX_ACTIVE_KEYS_PER_CUSTOMER} active api keys per customer; revoke one before minting another"
        )));
    }

    let created =
        keys_db::create_returning_plaintext(&state.db, &session.sub, name, &sub.tier).await?;
    Ok((
        StatusCode::CREATED,
        Json(MintResponse {
            api_key: created.plaintext,
            key: created.row.into(),
        }),
    ))
}

#[derive(Serialize)]
pub struct ListResponse {
    pub count: usize,
    pub keys: Vec<ApiKeyView>,
}

async fn list(
    State(state): State<AppState>,
    Extension(session): Extension<CustomerSession>,
) -> Result<Json<ListResponse>, ApiError> {
    let rows: Vec<keys_db::ApiKeyRow> = sqlx::query_as(
        r#"
        SELECT id, key_hash, key_prefix, customer_id, name, tier,
               created_at, last_used_at, revoked_at, usage_count
        FROM api_keys
        WHERE customer_id = $1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&session.sub)
    .fetch_all(&state.db)
    .await?;
    let keys: Vec<ApiKeyView> = rows.into_iter().map(Into::into).collect();
    Ok(Json(ListResponse {
        count: keys.len(),
        keys,
    }))
}

async fn revoke(
    State(state): State<AppState>,
    Extension(session): Extension<CustomerSession>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiKeyView>, ApiError> {
    // Lookup-then-update with ownership check. We could collapse it
    // into a single UPDATE WHERE id = $1 AND customer_id = $2 but
    // we still need to differentiate "not yours" from "doesn't
    // exist" for the 404. SELECT first, then revoke, is two queries
    // but read-then-act is fine because revoke is idempotent and
    // rare.
    let row: Option<keys_db::ApiKeyRow> = sqlx::query_as(
        r#"
        SELECT id, key_hash, key_prefix, customer_id, name, tier,
               created_at, last_used_at, revoked_at, usage_count
        FROM api_keys
        WHERE id = $1
        "#,
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::NotFound(format!("api key {id} not found")));
    };
    if row.customer_id != session.sub {
        // 404, NOT 403 — leaking "this id exists but isn't yours"
        // is a small information disclosure we don't want.
        return Err(ApiError::NotFound(format!("api key {id} not found")));
    }

    let revoked = keys_db::revoke(&state.db, id).await?;
    match revoked {
        Some(r) => Ok(Json(r.into())),
        None => Err(ApiError::NotFound(format!("api key {id} not found"))),
    }
}

// ----------------------- helpers -----------------------

#[derive(Debug, Clone)]
struct ActiveSubscription {
    tier: String,
    #[allow(dead_code)]
    status: String,
}

/// Look up the caller's subscription and reject the call if it's
/// not in a status that authorises new keys. Statuses that pass:
/// `active`, `trialing`. Everything else (past_due, canceled,
/// unpaid, …) returns 403 with a runbook hint — the customer must
/// resolve their billing before minting more keys.
async fn fetch_active_subscription(
    state: &AppState,
    stripe_customer_id: &str,
) -> Result<ActiveSubscription, ApiError> {
    let row: Option<(String, String)> = sqlx::query_as(
        r#"
        SELECT tier, status FROM subscriptions
        WHERE stripe_customer_id = $1
        "#,
    )
    .bind(stripe_customer_id)
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some((tier, status)) if matches!(status.as_str(), "active" | "trialing") => {
            Ok(ActiveSubscription { tier, status })
        }
        Some((_, status)) => Err(ApiError::Unauthorized(format!(
            "no active customer subscription (status: {status})"
        ))),
        None => Err(ApiError::Unauthorized(
            "no active customer subscription".into(),
        )),
    }
}

async fn count_active_keys_for_customer(
    pool: &sqlx::PgPool,
    customer_id: &str,
) -> Result<i64, sqlx::Error> {
    let row: (i64,) = sqlx::query_as(
        r#"
        SELECT COUNT(*) FROM api_keys
        WHERE customer_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(customer_id)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}
