//! Customer-facing metered endpoints (Sprint 4 PR 5).
//!
//! Everything under `/v1/metered/*` sits behind `require_api_key`.
//! A caller presents an `aex_live_...` plaintext on either the
//! `X-API-Key` header (recommended — matches Stripe/common SaaS
//! convention) or `Authorization: Bearer …` (browser fetch() against
//! the metered surface without a custom-header CORS preflight).
//!
//! On success the middleware inserts an [`ApiKeyContext`] into the
//! request extensions. Handlers pull it via `Extension<ApiKeyContext>`
//! to know which paying customer (and tier) made the call. Revenue
//! features (quota enforcement, usage attribution, per-customer
//! dashboards) grow on this surface.
//!
//! We deliberately do NOT retrofit API-key auth onto the Sprint 2
//! signed-wire endpoints (`/v1/agents/*`, `/v1/transfers/*`,
//! `/v1/inbox`). Those use canonical-bytes Ed25519 signatures for
//! authentication — that's their entire security model. Layering a
//! second auth mechanism on top adds complexity without increasing
//! security and would break the existing SDK contracts.

use axum::{
    extract::{Extension, Request, State},
    http::{header::AUTHORIZATION, HeaderMap},
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;

use crate::{db::api_keys as keys_db, error::ApiError, AppState};

/// Request-scoped context populated by [`require_api_key`] after a
/// successful lookup. Handlers downstream of the middleware pull it
/// via `Extension<ApiKeyContext>`.
///
/// We carry `key_prefix` (not the full plaintext or the hash) so
/// handlers can echo the truncated form in responses and logs —
/// useful for the whoami / usage-dashboard UX without ever exposing
/// the secret material.
#[derive(Clone, Debug)]
pub struct ApiKeyContext {
    pub id: uuid::Uuid,
    pub customer_id: String,
    pub tier: String,
    pub key_prefix: String,
}

/// Expected plaintext form: `aex_live_` + 32 hex chars = 41 bytes.
/// Enforced at the middleware before we hash-and-look-up so an
/// obviously-malformed header trips 401 without a DB round-trip.
const EXPECTED_PLAINTEXT_LEN: usize = 41;
const LIVE_PREFIX: &str = "aex_live_";

/// Middleware that authenticates the caller by their API key.
///
/// Resolution order:
///
/// 1. `X-API-Key: aex_live_…` — recommended. Matches Stripe's form
///    and is the shape documented in SDK examples.
/// 2. `Authorization: Bearer aex_live_…` — fallback. Lets browser
///    `fetch()` calls against the metered surface skip the custom-
///    header CORS preflight; useful for the future in-browser
///    dashboard.
///
/// Failure modes (all 401, differentiated by `runbook_url`):
///
/// - No header → `api-key-missing.md`
/// - Header present but malformed (wrong prefix / wrong length) →
///   `api-key-invalid.md`
/// - Header present, well-formed, but no matching active row →
///   `api-key-invalid.md`
///
/// On success the middleware spawns a fire-and-forget task to bump
/// `usage_count` + `last_used_at`. We accept the tiny drift under
/// concurrent writes in exchange for keeping the hot path below
/// ~1ms of per-request overhead.
pub async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let plaintext = match extract_plaintext(request.headers()) {
        Ok(p) => p,
        Err(e) => return e.into_response(),
    };

    let hash = keys_db::hash_plaintext(&plaintext);
    let row = match keys_db::find_active_by_hash(&state.db, &hash).await {
        Ok(Some(r)) => r,
        Ok(None) => return invalid_response(),
        Err(e) => return ApiError::internal(e).into_response(),
    };

    let ctx = ApiKeyContext {
        id: row.id,
        customer_id: row.customer_id.clone(),
        tier: row.tier.clone(),
        key_prefix: row.key_prefix.clone(),
    };
    request.extensions_mut().insert(ctx);

    // Fire-and-forget usage bump. The response ships the moment the
    // handler finishes; we don't block on the UPDATE.
    let pool = state.db.clone();
    let id = row.id;
    tokio::spawn(async move {
        if let Err(e) = keys_db::bump_usage(&pool, id).await {
            tracing::warn!(
                error = %e,
                api_key_id = %id,
                "failed to bump api_key usage counter"
            );
        }
    });

    next.run(request).await
}

/// Pull the plaintext key out of the request headers. Returns a
/// pre-rendered [`ApiError`] on failure so the caller can short-
/// circuit with `.into_response()`.
fn extract_plaintext(headers: &HeaderMap) -> Result<String, ApiError> {
    // X-API-Key wins over Authorization — if both are present we
    // treat the explicit custom header as authoritative. Prevents
    // surprise when an SDK sets both for compatibility.
    let candidate = headers
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer "))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        });

    let Some(plaintext) = candidate else {
        return Err(ApiError::Unauthorized("api key required".into()));
    };

    if plaintext.len() != EXPECTED_PLAINTEXT_LEN || !plaintext.starts_with(LIVE_PREFIX) {
        return Err(ApiError::Unauthorized("api key not recognized".into()));
    }

    Ok(plaintext.to_owned())
}

fn invalid_response() -> Response {
    ApiError::Unauthorized("api key not recognized".into()).into_response()
}

#[derive(Serialize)]
struct WhoAmIResponse {
    customer_id: String,
    tier: String,
    key_prefix: String,
}

/// Debug endpoint: echoes the authenticated caller's identity.
/// Useful as a post-deploy smoke test and as a SDK integration
/// sanity check ("does my key work?"). Real metered endpoints
/// (transfers-by-api-key, usage queries) land in follow-up PRs.
async fn whoami(Extension(ctx): Extension<ApiKeyContext>) -> Json<WhoAmIResponse> {
    Json(WhoAmIResponse {
        customer_id: ctx.customer_id,
        tier: ctx.tier,
        key_prefix: ctx.key_prefix,
    })
}

pub fn router() -> Router<AppState> {
    Router::new().route("/whoami", get(whoami))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue};

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn extract_rejects_missing_header() {
        let err = extract_plaintext(&HeaderMap::new()).unwrap_err();
        match err {
            ApiError::Unauthorized(m) => assert!(m.contains("required")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn extract_accepts_x_api_key() {
        // 41-char well-formed plaintext.
        let plaintext = "aex_live_0123456789abcdef0123456789abcdef";
        let got = extract_plaintext(&headers_with("x-api-key", plaintext)).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn extract_accepts_authorization_bearer() {
        let plaintext = "aex_live_0123456789abcdef0123456789abcdef";
        let got = extract_plaintext(&headers_with(
            "authorization",
            &format!("Bearer {plaintext}"),
        ))
        .unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn extract_prefers_x_api_key_when_both_present() {
        let primary = "aex_live_0123456789abcdef0123456789abcdef";
        let fallback = "aex_live_ffffffffffffffffffffffffffffffff";
        let mut h = HeaderMap::new();
        h.insert("x-api-key", HeaderValue::from_str(primary).unwrap());
        h.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {fallback}")).unwrap(),
        );
        assert_eq!(extract_plaintext(&h).unwrap(), primary);
    }

    #[test]
    fn extract_rejects_wrong_prefix() {
        // Same length, wrong prefix — an admin bearer token, say.
        let wrong = "aex_test_0123456789abcdef0123456789abcdef";
        let err = extract_plaintext(&headers_with("x-api-key", wrong)).unwrap_err();
        match err {
            ApiError::Unauthorized(m) => assert!(m.contains("not recognized")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_wrong_length() {
        let too_short = "aex_live_abc";
        let err = extract_plaintext(&headers_with("x-api-key", too_short)).unwrap_err();
        match err {
            ApiError::Unauthorized(m) => assert!(m.contains("not recognized")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_empty_value() {
        // Whitespace-only value is treated the same as missing.
        let err = extract_plaintext(&headers_with("x-api-key", "   ")).unwrap_err();
        match err {
            ApiError::Unauthorized(m) => assert!(m.contains("required")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn extract_rejects_non_bearer_authorization() {
        // `Basic ...` or any non-Bearer scheme falls through to "no
        // acceptable header" → missing.
        let err = extract_plaintext(&headers_with("authorization", "Basic abc==")).unwrap_err();
        match err {
            ApiError::Unauthorized(m) => assert!(m.contains("required")),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }
}
