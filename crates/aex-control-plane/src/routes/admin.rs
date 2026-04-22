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
    extract::{Request, State},
    http::{header::AUTHORIZATION, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;
use subtle::ConstantTimeEq;

use crate::AppState;

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

pub fn router() -> Router<AppState> {
    // Individual admin endpoints accumulate here over Sprint 4 (API
    // keys, usage queries, grandfather coupon issuance). All inherit
    // the bearer-token gate applied in `build_app_with_cors`.
    Router::new().route("/whoami", get(whoami))
}
