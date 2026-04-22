//! Admin-only endpoints, gated by a shared bearer token (Sprint 4).
//!
//! Everything under `/v1/admin/*` requires `Authorization: Bearer
//! <AEX_ADMIN_TOKEN>`. The token lives in `AppState::admin_token`;
//! middleware rejects requests that miss it entirely (401), present a
//! wrong token (403), or reach a server that forgot to configure the
//! secret (503). The compare is constant-time via [`subtle`] so a
//! timing oracle can't reveal the token one byte at a time.
//!
//! This module deliberately does NOT implement user accounts or
//! multi-role ACLs. The Sprint 4 surface (API-key management, usage
//! dashboard, grandfathered-plan signup) is small enough that a
//! single shared ops token is the right abstraction. If we later
//! grow a real admin UI with operator identities, this gate becomes
//! the first hop; per-operator auth plugs in behind it.

use axum::{
    extract::{Path, Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use time::OffsetDateTime;

use crate::{db::api_keys as keys_db, error::ApiError, AppState};

/// Minimum header length after trimming `Bearer `. Matches the
/// config-time `MIN_ADMIN_TOKEN_LEN`, enforced separately from the
/// server's own token to reject obviously-garbage requests before
/// any compare runs.
const MIN_BEARER_LEN: usize = 32;

/// Extract and verify the `Authorization: Bearer <token>` header.
/// Returns `Ok(())` on success. The error statuses are intentional:
///
/// - `503 Service Unavailable` — the server has no admin token
///   configured (probably a misconfigured deploy). Distinct from 4xx
///   so ops don't confuse "wrong token" with "forgot to set it".
/// - `401 Unauthorized` — header missing or malformed.
/// - `403 Forbidden` — header present but token doesn't match.
pub async fn require_admin_token(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(expected) = state.admin_token.as_deref() else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "admin_disabled",
            "admin endpoints disabled on this server — set AEX_ADMIN_TOKEN and restart",
        );
    };

    let header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let presented = match header.and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) if t.len() >= MIN_BEARER_LEN => t,
        _ => {
            return error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing or malformed bearer token",
            );
        }
    };

    // Constant-time: trick is that short-circuiting `==` leaks
    // length-mismatch-at-byte-N in the instruction count. `ct_eq`
    // scans the whole byte slice regardless.
    let a = presented.as_bytes();
    let b = expected.as_bytes();
    let equal_len = a.len() == b.len();
    let equal_bytes = if equal_len {
        a.ct_eq(b).unwrap_u8() == 1
    } else {
        // Still do a compare against a same-length prefix so the
        // compare cost doesn't vary with the attacker's input. Any
        // mismatch is a 403; the `ct_eq` result is discarded.
        let _ = a[..a.len().min(b.len())].ct_eq(&b[..a.len().min(b.len())]);
        false
    };
    if !equal_bytes {
        return error(StatusCode::FORBIDDEN, "forbidden", "invalid admin token");
    }

    next.run(request).await
}

/// Admin-specific error body. Mirrors the top-level `ErrorBody` shape
/// but lives here so the middleware can emit responses without going
/// through `ApiError` (which doesn't have SERVICE_UNAVAILABLE or
/// FORBIDDEN variants today — we don't want to bloat the main type
/// for two admin-only cases).
#[derive(Serialize)]
struct AdminErrorBody<'a> {
    code: &'a str,
    message: &'a str,
}

fn error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (status, Json(AdminErrorBody { code, message })).into_response()
}

#[derive(Serialize)]
struct WhoAmIResponse {
    /// Constant marker so the caller can distinguish this from a
    /// silently-redirected 200 on some upstream proxy. If the marker
    /// is missing, the request didn't reach the real admin endpoint.
    ok: bool,
    service: &'static str,
    version: &'static str,
}

/// Trivial probe that a caller (ops, deploy smoke-test) can hit to
/// verify (a) the admin token is configured server-side and (b) the
/// token they're holding actually works.
async fn whoami(State(_): State<AppState>) -> Json<WhoAmIResponse> {
    Json(WhoAmIResponse {
        ok: true,
        service: "aex-control-plane",
        version: env!("CARGO_PKG_VERSION"),
    })
}

// ---------- API key CRUD ----------

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    /// Opaque customer identifier. Today: Stripe customer_id post-
    /// checkout, or a UUID / email for grandfathered users. The CP
    /// doesn't interpret the value; policy code uses it as a
    /// foreign-key-ish handle.
    pub customer_id: String,
    /// Human-readable label shown in admin/dashboard UIs.
    pub name: String,
    /// Subscription tier. Free-text at the wire layer; the policy
    /// engine enforces known values.
    #[serde(default = "default_tier")]
    pub tier: String,
}

fn default_tier() -> String {
    "free".into()
}

/// Shape returned on GET /list and after revoke. The plaintext is
/// NEVER present here — it's exposed only once, on the creation
/// response, as `CreateApiKeyResponse::api_key`.
#[derive(Debug, Serialize)]
pub struct ApiKeyView {
    pub id: uuid::Uuid,
    pub key_prefix: String,
    pub customer_id: String,
    pub name: String,
    pub tier: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_used_at: Option<OffsetDateTime>,
    #[serde(
        with = "time::serde::rfc3339::option",
        skip_serializing_if = "Option::is_none"
    )]
    pub revoked_at: Option<OffsetDateTime>,
    pub usage_count: i64,
}

impl From<keys_db::ApiKeyRow> for ApiKeyView {
    fn from(r: keys_db::ApiKeyRow) -> Self {
        Self {
            id: r.id,
            key_prefix: r.key_prefix,
            customer_id: r.customer_id,
            name: r.name,
            tier: r.tier,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            revoked_at: r.revoked_at,
            usage_count: r.usage_count,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    #[serde(flatten)]
    pub key: ApiKeyView,
    /// THE plaintext key. Shown exactly once — the caller MUST
    /// persist it here (typically handed to the customer); once
    /// dropped it cannot be retrieved from the CP.
    pub api_key: String,
}

async fn create_api_key(
    State(state): State<AppState>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
    if req.customer_id.is_empty() {
        return Err(ApiError::BadRequest("customer_id is empty".into()));
    }
    if req.name.is_empty() {
        return Err(ApiError::BadRequest("name is empty".into()));
    }
    if req.tier.is_empty() {
        return Err(ApiError::BadRequest("tier is empty".into()));
    }

    let created =
        keys_db::create_returning_plaintext(&state.db, &req.customer_id, &req.name, &req.tier)
            .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            api_key: created.plaintext,
            key: created.row.into(),
        }),
    ))
}

#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub count: usize,
    pub keys: Vec<ApiKeyView>,
}

/// Cap at 500 keys per call. Pagination is future work; alpha tier
/// with grandfather plan + a handful of team-tier customers stays
/// well under this.
const LIST_LIMIT: i64 = 500;

async fn list_api_keys(
    State(state): State<AppState>,
) -> Result<Json<ListApiKeysResponse>, ApiError> {
    let rows = keys_db::list_all(&state.db, LIST_LIMIT).await?;
    let keys: Vec<ApiKeyView> = rows.into_iter().map(Into::into).collect();
    Ok(Json(ListApiKeysResponse {
        count: keys.len(),
        keys,
    }))
}

async fn revoke_api_key(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiKeyView>, ApiError> {
    match keys_db::revoke(&state.db, id).await? {
        Some(row) => Ok(Json(row.into())),
        None => Err(ApiError::NotFound(format!("api key {} not found", id))),
    }
}

pub fn router() -> Router<AppState> {
    // Individual admin endpoints accumulate here over Sprint 4 (API
    // keys, usage queries, grandfather coupon issuance). All inherit
    // the bearer-token gate applied in `routes::v1_router`.
    Router::new()
        .route("/whoami", get(whoami))
        .route("/api-keys", post(create_api_key).get(list_api_keys))
        .route("/api-keys/:id", delete(revoke_api_key))
}
