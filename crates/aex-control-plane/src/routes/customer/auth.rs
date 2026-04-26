//! Customer authentication: magic-link request/verify + session
//! middleware (Sprint 4 PR 7).

use axum::{
    extract::{Request, State},
    http::{
        header::{HeaderValue, COOKIE, SET_COOKIE},
        StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    db::{customers as customers_db, magic_link_tokens as link_db},
    email::{self, MagicLinkEmail},
    error::ApiError,
    session::{self, CustomerSession, SessionError},
    AppState,
};

/// Magic-link lifetime. Stripe-style — the link expires fast enough
/// to deny use of a leaked email body but long enough for a human
/// to read the email and click.
const MAGIC_LINK_TTL: time::Duration = time::Duration::minutes(15);
/// Hard cap on session lifetime. Aligns with `session::DEFAULT_TTL_SECS`
/// here for clarity at the call site.
const SESSION_TTL_SECS: i64 = session::DEFAULT_TTL_SECS;
/// Where to set the cookie's Domain attribute. Pulled from the frontend
/// base URL so dev (`http://localhost:3000`) gets a host-only cookie
/// while prod (`https://spize.io`) gets `.spize.io` for cross-subdomain.
///
/// Hostnames are compared **exactly** via `url::Url`, NOT via
/// `starts_with`, so a malicious config like
/// `https://spize.io.evil.com` does not get treated as a `spize.io`
/// subdomain (which would let an attacker who controls the
/// frontend-base-url config steal the session cookie).
fn cookie_domain_from_frontend(frontend_url: &str) -> Option<String> {
    let url = url::Url::parse(frontend_url).ok()?;
    let host = url.host_str()?;
    if host == "spize.io" || host == "www.spize.io" {
        Some(".spize.io".into())
    } else {
        // Localhost / staging — host-only cookie. Browsers fall back
        // to host-only when Domain is omitted.
        None
    }
}

// ---------------- public router ----------------

pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/auth/magic-link/request", post(magic_link_request))
        .route("/auth/magic-link/verify", post(magic_link_verify))
}

pub fn authed_router() -> Router<AppState> {
    Router::new()
        .route("/auth/whoami", get(whoami))
        .route("/auth/logout", post(logout))
}

// ---------------- magic-link request ----------------

#[derive(Deserialize)]
pub struct MagicLinkRequestBody {
    pub email: String,
}

#[derive(Serialize)]
pub struct MagicLinkRequestResponse {
    /// Always `true` regardless of whether the email is a known
    /// customer — privacy-preserving (don't leak which addresses
    /// have accounts).
    pub sent: bool,
    /// Present only when the server is running in dev-mode (no
    /// `RESEND_API_KEY` configured) AND the email belonged to a
    /// real customer. Lets developers exercise the verify endpoint
    /// without a working SMTP loop.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_token: Option<String>,
}

async fn magic_link_request(
    State(state): State<AppState>,
    Json(req): Json<MagicLinkRequestBody>,
) -> Result<Json<MagicLinkRequestResponse>, ApiError> {
    if !state.customer_auth.is_ready() {
        return Err(ApiError::Internal(Box::new(crate::error::SimpleError(
            "customer auth not configured".into(),
        ))));
    }

    let email = req.email.trim().to_ascii_lowercase();
    if email.is_empty() || !email.contains('@') {
        return Err(ApiError::BadRequest("email is missing or malformed".into()));
    }

    // Privacy: same response shape whether or not the email is a
    // paying customer. We branch only on the work we do internally.
    let Some(customer) = customers_db::find_by_email(&state.db, &email).await? else {
        tracing::info!(email, "magic-link request for unknown email; silent 200");
        return Ok(Json(MagicLinkRequestResponse {
            sent: true,
            dev_token: None,
        }));
    };

    let now = state.clock.now();
    let (_, plaintext) = link_db::create(
        &state.db,
        &customer.stripe_customer_id,
        &email,
        MAGIC_LINK_TTL,
        now,
    )
    .await?;

    let frontend = state.customer_auth.frontend_base_url.as_deref().unwrap();
    let link = format!("{frontend}/auth/callback?token={plaintext}");

    if state.email.resend_api_key.is_some() {
        let msg = MagicLinkEmail {
            to: &email,
            link: &link,
            expires_in: "15 minutes",
        };
        if let Err(e) = email::send_magic_link(&state.email, &msg).await {
            tracing::error!(error = %e, email, "failed to deliver magic-link email");
            // Still report success to the caller — the customer can
            // retry. We don't want to surface the upstream failure
            // because that's a side-channel (does this email exist?).
        } else {
            tracing::info!(email, customer = %customer.stripe_customer_id, "sent magic-link");
        }
        Ok(Json(MagicLinkRequestResponse {
            sent: true,
            dev_token: None,
        }))
    } else {
        // Dev mode: no email provider configured, return the token
        // in the response body so a developer can curl-verify
        // without a real inbox.
        tracing::warn!(
            email,
            customer = %customer.stripe_customer_id,
            "RESEND_API_KEY unset; returning magic-link token in response (dev mode)"
        );
        Ok(Json(MagicLinkRequestResponse {
            sent: true,
            dev_token: Some(plaintext),
        }))
    }
}

// ---------------- magic-link verify ----------------

#[derive(Deserialize)]
pub struct MagicLinkVerifyBody {
    pub token: String,
}

#[derive(Serialize)]
pub struct MagicLinkVerifyResponse {
    pub stripe_customer_id: String,
    pub email: String,
}

async fn magic_link_verify(
    State(state): State<AppState>,
    Json(req): Json<MagicLinkVerifyBody>,
) -> Result<Response, ApiError> {
    if !state.customer_auth.is_ready() {
        return Err(ApiError::Internal(Box::new(crate::error::SimpleError(
            "customer auth not configured".into(),
        ))));
    }
    let secret = state.customer_auth.session_secret.as_deref().unwrap();
    let frontend = state.customer_auth.frontend_base_url.as_deref().unwrap();

    let now = state.clock.now();
    let outcome = link_db::consume(&state.db, req.token.trim(), now).await?;

    use link_db::ConsumeOutcome;
    let row = match outcome {
        ConsumeOutcome::Consumed(r) => r,
        ConsumeOutcome::NotFound => {
            return Err(ApiError::Unauthorized("magic link not recognized".into()));
        }
        ConsumeOutcome::Expired => {
            return Err(ApiError::Unauthorized("magic link expired".into()));
        }
        ConsumeOutcome::AlreadyUsed => {
            return Err(ApiError::Unauthorized("magic link already used".into()));
        }
    };

    // Session JWT issued with wall-clock unix time. We don't use
    // `state.clock` here because `jsonwebtoken::decode` internally
    // checks `exp` against `chrono::Utc::now()`; mismatched
    // issued-at + verify-at clocks would make every JWT we mint
    // immediately expired. The magic-link flow's own expiry uses
    // `state.clock` because we control both ends in DB SQL.
    let session_now = time::OffsetDateTime::now_utc().unix_timestamp();
    let token = session::issue(
        secret,
        &row.stripe_customer_id,
        SESSION_TTL_SECS,
        session_now,
    )
    .map_err(|_| ApiError::Internal(Box::new(crate::error::SimpleError("session issue".into()))))?;

    let domain = cookie_domain_from_frontend(frontend);
    let cookie = session::set_cookie_header(&token, SESSION_TTL_SECS, domain.as_deref());

    let body = MagicLinkVerifyResponse {
        stripe_customer_id: row.stripe_customer_id,
        email: row.email,
    };
    let mut resp = (StatusCode::OK, Json(body)).into_response();
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    Ok(resp)
}

// ---------------- session middleware ----------------

/// Pull the `aex_session=…` cookie off a comma-separated cookie
/// header. We don't need the full grammar of RFC 6265 because we
/// set the cookie ourselves — a simple `name=value` split is
/// sufficient.
fn extract_session_cookie(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers.get(COOKIE).and_then(|v| v.to_str().ok())?;
    for pair in header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name == session::COOKIE_NAME {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub async fn require_customer_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(secret) = state.customer_auth.session_secret.as_deref() else {
        return ApiError::Internal(Box::new(crate::error::SimpleError(
            "customer auth not configured".into(),
        )))
        .into_response();
    };

    let Some(token) = extract_session_cookie(request.headers()) else {
        return ApiError::Unauthorized("session cookie missing".into()).into_response();
    };

    let claims = match session::verify(secret, &token) {
        Ok(c) => c,
        Err(SessionError::Expired) => {
            return ApiError::Unauthorized("session expired".into()).into_response();
        }
        Err(_) => {
            return ApiError::Unauthorized("session invalid".into()).into_response();
        }
    };

    request.extensions_mut().insert(claims);
    next.run(request).await
}

// ---------------- whoami / logout ----------------

#[derive(Serialize)]
struct WhoAmIResponse {
    stripe_customer_id: String,
    expires_at_unix: i64,
}

async fn whoami(axum::Extension(claims): axum::Extension<CustomerSession>) -> Json<WhoAmIResponse> {
    Json(WhoAmIResponse {
        stripe_customer_id: claims.sub,
        expires_at_unix: claims.exp,
    })
}

async fn logout(State(state): State<AppState>) -> Response {
    let domain = state
        .customer_auth
        .frontend_base_url
        .as_deref()
        .and_then(cookie_domain_from_frontend);
    let cookie = session::clear_cookie_header(domain.as_deref());

    let mut resp = (StatusCode::OK, Json(json!({"logged_out": true}))).into_response();
    resp.headers_mut()
        .insert(SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn extract_session_cookie_picks_named_pair() {
        let mut h = HeaderMap::new();
        h.insert(
            COOKIE,
            "other=1; aex_session=abc123; foo=bar".parse().unwrap(),
        );
        assert_eq!(extract_session_cookie(&h), Some("abc123".into()));
    }

    #[test]
    fn extract_session_cookie_returns_none_when_absent() {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, "foo=bar; baz=qux".parse().unwrap());
        assert!(extract_session_cookie(&h).is_none());
    }

    #[test]
    fn cookie_domain_for_prod_is_dot_spize_io() {
        assert_eq!(
            cookie_domain_from_frontend("https://spize.io"),
            Some(".spize.io".into())
        );
        assert_eq!(
            cookie_domain_from_frontend("https://spize.io/dashboard"),
            Some(".spize.io".into())
        );
    }

    #[test]
    fn cookie_domain_for_dev_is_none() {
        assert!(cookie_domain_from_frontend("http://localhost:3000").is_none());
        assert!(cookie_domain_from_frontend("https://staging.example.com").is_none());
    }

    #[test]
    fn cookie_domain_rejects_lookalike_hostnames() {
        // Regression: an attacker who controls the frontend-base-url
        // config must not be able to coax `.spize.io` out of the
        // cookie path by picking a lookalike host.
        assert!(cookie_domain_from_frontend("https://spize.io.evil.com").is_none());
        assert!(cookie_domain_from_frontend("https://evilspize.io").is_none());
        assert!(cookie_domain_from_frontend("https://spize.iox").is_none());
    }
}
