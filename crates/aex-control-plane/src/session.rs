//! Customer dashboard session JWT (Sprint 4 PR 7).
//!
//! Sessions are stateless HS256 JWTs stored in a `aex_session`
//! cookie. The middleware verifies the cookie's signature against
//! `CustomerAuthConfig.session_secret` and resolves
//! `claims.sub → stripe_customer_id` for downstream handlers.
//!
//! # Why JWT (not server-side sessions)
//!
//! For an MVP one-process control plane the trade-off doesn't yet
//! matter — both work. JWT keeps the data path stateless, which
//! pays off when the CP scales to multiple Fly machines: any
//! machine can validate any session without DB consultation.
//!
//! Trade: revocation costs an extra hop (we'd need a small
//! `revoked_sessions` table once we want to log a customer out
//! mid-token-lifetime). Acceptable for MVP — keys are renewable
//! anyway and the dashboard UX doesn't require precision logout.
//!
//! # Cookie attributes
//!
//! - `Domain=.spize.io`: shared across `spize.io` (frontend) and
//!   `api.spize.io` (control plane).
//! - `SameSite=None; Secure`: required when sharing across
//!   subdomains via cross-origin fetch from the dashboard.
//! - `HttpOnly`: JS on the dashboard cannot read it — XSS that
//!   slips into the SPA still can't steal the session.
//! - `Max-Age` defaults to 30 days; configurable per-call.

use jsonwebtoken::{
    decode, encode, errors::ErrorKind as JwtErrorKind, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use serde::{Deserialize, Serialize};

/// Default session lifetime. 30 days is the dashboard standard for
/// dev tooling — long enough to skip re-login on most workdays,
/// short enough that a stolen cookie expires before it's
/// indefinitely useful.
pub const DEFAULT_TTL_SECS: i64 = 30 * 24 * 3600;

/// Session cookie name. Constant so the dashboard frontend reads
/// the same one.
pub const COOKIE_NAME: &str = "aex_session";

/// What a verified JWT yields downstream. Handlers under
/// `/v1/customer/*` pull this via `Extension<CustomerSession>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomerSession {
    /// `stripe_customer_id` — the subject of the session.
    pub sub: String,
    /// Unix-seconds issued-at.
    pub iat: i64,
    /// Unix-seconds expires-at.
    pub exp: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("session feature not configured (AEX_SESSION_SECRET unset)")]
    NotConfigured,
    #[error("session token invalid")]
    InvalidToken,
    #[error("session token expired")]
    Expired,
}

/// Mint a JWT for `customer_id` valid for `ttl_secs` from `now_unix`.
/// `secret` MUST be the same value the verify path uses; rotating
/// it invalidates every session in flight (intentional break-glass).
pub fn issue(
    secret: &str,
    customer_id: &str,
    ttl_secs: i64,
    now_unix: i64,
) -> Result<String, SessionError> {
    if secret.is_empty() {
        return Err(SessionError::NotConfigured);
    }
    let claims = CustomerSession {
        sub: customer_id.to_string(),
        iat: now_unix,
        exp: now_unix + ttl_secs,
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| SessionError::InvalidToken)
}

/// Verify a JWT and return the decoded session. Wraps
/// `jsonwebtoken::decode` with our error type so handlers don't
/// import the underlying crate.
pub fn verify(secret: &str, token: &str) -> Result<CustomerSession, SessionError> {
    if secret.is_empty() {
        return Err(SessionError::NotConfigured);
    }
    let mut validation = Validation::new(Algorithm::HS256);
    // We don't use a fixed `iss`/`aud` so disable those checks.
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    validation.required_spec_claims.insert("exp".to_string());
    // The default 60s leeway is convenient for distributed clocks,
    // but for a single-process control plane it just delays expiry
    // detection. Drop it so `exp <= now` is a hard rejection — keeps
    // tests deterministic too.
    validation.leeway = 0;
    let data = decode::<CustomerSession>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        JwtErrorKind::ExpiredSignature => SessionError::Expired,
        _ => SessionError::InvalidToken,
    })?;
    Ok(data.claims)
}

/// Build the `Set-Cookie` header value for the session JWT. We
/// hand-build the string instead of using `cookie::Cookie::to_string`
/// so the attribute set is exactly what the dashboard expects and
/// reviewable in one place.
///
/// `domain = None` produces a host-only cookie (dev/laptop). In
/// prod the caller passes `Some(".spize.io")`.
pub fn set_cookie_header(token: &str, max_age_secs: i64, domain: Option<&str>) -> String {
    let mut parts: Vec<String> = vec![
        format!("{COOKIE_NAME}={token}"),
        "Path=/".into(),
        format!("Max-Age={max_age_secs}"),
        "HttpOnly".into(),
        "Secure".into(),
        "SameSite=None".into(),
    ];
    if let Some(d) = domain {
        parts.insert(1, format!("Domain={d}"));
    }
    parts.join("; ")
}

/// Build the `Set-Cookie` header value that EXPIRES the session
/// (logout flow). Uses `Max-Age=0` so the browser drops the cookie
/// immediately.
pub fn clear_cookie_header(domain: Option<&str>) -> String {
    let mut parts: Vec<String> = vec![
        format!("{COOKIE_NAME}=deleted"),
        "Path=/".into(),
        "Max-Age=0".into(),
        "HttpOnly".into(),
        "Secure".into(),
        "SameSite=None".into(),
    ];
    if let Some(d) = domain {
        parts.insert(1, format!("Domain={d}"));
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    const SECRET: &str = "012345678901234567890123456789ab"; // 32 chars

    fn now() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let now = now();
        let token = issue(SECRET, "cus_abc", 3600, now).unwrap();
        let claims = verify(SECRET, &token).unwrap();
        assert_eq!(claims.sub, "cus_abc");
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp, now + 3600);
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let token = issue(SECRET, "cus_abc", 3600, now()).unwrap();
        let err = verify("OTHER_SECRET_xxxxxxxxxxxxxxxxxxxxxxx", &token).unwrap_err();
        assert!(matches!(err, SessionError::InvalidToken));
    }

    #[test]
    fn verify_rejects_expired() {
        // Negative ttl pins exp into the past relative to wall clock,
        // so jsonwebtoken's exp check fires immediately.
        let token = issue(SECRET, "cus_abc", -10, now()).unwrap();
        let err = verify(SECRET, &token).unwrap_err();
        assert!(matches!(err, SessionError::Expired));
    }

    #[test]
    fn set_cookie_header_has_required_attributes() {
        let h = set_cookie_header("token123", 3600, Some(".spize.io"));
        assert!(h.starts_with("aex_session=token123;"));
        assert!(h.contains("Domain=.spize.io"));
        assert!(h.contains("Max-Age=3600"));
        assert!(h.contains("HttpOnly"));
        assert!(h.contains("Secure"));
        assert!(h.contains("SameSite=None"));
    }

    #[test]
    fn clear_cookie_header_zeros_max_age() {
        let h = clear_cookie_header(Some(".spize.io"));
        assert!(h.contains("Max-Age=0"));
    }

    #[test]
    fn issue_rejects_empty_secret() {
        let err = issue("", "x", 1, 0).unwrap_err();
        assert!(matches!(err, SessionError::NotConfigured));
    }
}
