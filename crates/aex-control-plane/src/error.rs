//! HTTP error type.
//!
//! We deliberately do NOT implement `From<anyhow::Error>` or catch-all
//! variants — each call site must decide whether a failure is a client error
//! (400/404/409), an auth error (401/403), or a server error (500). That
//! discipline is what keeps error responses honest and audit entries
//! meaningful.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("internal error")]
    Internal(#[source] anyhow_like::BoxedError),
}

impl ApiError {
    pub fn internal<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Internal(Box::new(err))
    }

    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::Unauthorized(_) => "unauthorized",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Internal(_) => "internal_error",
        }
    }

    /// User-facing message. Internal errors are masked — the full detail
    /// goes to tracing, not to the wire.
    fn public_message(&self) -> String {
        match self {
            ApiError::BadRequest(m)
            | ApiError::Unauthorized(m)
            | ApiError::NotFound(m)
            | ApiError::Conflict(m) => m.clone(),
            ApiError::Internal(_) => "internal server error".into(),
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
    /// Operator-facing runbook URL. Mapped from `code` + a keyword
    /// scan of `message` via [`runbook::runbook_url`]. Absent when no
    /// specific runbook covers the failure mode so older SDKs see an
    /// unchanged shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    runbook_url: Option<&'static str>,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(ref err) = self {
            tracing::error!(error = %err, "internal error serving request");
        }
        let status = self.status();
        let code = self.code();
        let message = self.public_message();
        let body = ErrorBody {
            code,
            runbook_url: runbook::runbook_url(code, &message),
            message,
        };
        (status, Json(body)).into_response()
    }
}

impl From<aex_core::Error> for ApiError {
    fn from(err: aex_core::Error) -> Self {
        use aex_core::Error::*;
        match err {
            InvalidAgentId(m) => ApiError::BadRequest(format!("invalid agent_id: {}", m)),
            UnknownIdentityScheme => ApiError::BadRequest("unknown identity scheme".into()),
            SignatureInvalid => ApiError::Unauthorized("signature verification failed".into()),
            SignatureFormat(m) => ApiError::BadRequest(format!("bad signature: {}", m)),
            KeyUnavailable(m) => {
                ApiError::Internal(Box::new(SimpleError(format!("key unavailable: {}", m))))
            }
            NotFound(m) => ApiError::NotFound(m),
            Io(e) => ApiError::Internal(Box::new(e)),
            Crypto(m) => ApiError::BadRequest(format!("crypto error: {}", m)),
            Internal(m) => ApiError::Internal(Box::new(SimpleError(m))),
        }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => ApiError::NotFound("row not found".into()),
            other => ApiError::Internal(Box::new(other)),
        }
    }
}

/// Local wrapper so we avoid pulling `anyhow`.
pub mod anyhow_like {
    pub type BoxedError = Box<dyn std::error::Error + Send + Sync + 'static>;
}

/// Error → runbook URL mapping (Sprint 3 Delight #3).
///
/// Every non-generic failure has a corresponding Markdown page under
/// `docs/runbooks/<slug>.md` describing symptoms, likely causes, and
/// remediation. The CP attaches the URL to the JSON error body so
/// operators can jump to it straight from the SDK exception without
/// grepping source.
///
/// URLs point at the GitHub blob of the current `master` branch. If
/// the repo moves this constant is the only thing to update.
pub mod runbook {
    /// Base URL for published runbooks. Pinned to `master` so the link
    /// resolves as long as the repo is public; deeper version pinning
    /// (tag-specific runbooks) is out of scope until runbooks diverge
    /// across versions.
    pub const BASE_URL: &str = "https://github.com/icaroholding/aex/blob/master/docs/runbooks";

    /// Map `code` + message keywords to a runbook URL. `None` means
    /// "no specific runbook exists for this failure yet" — the field
    /// is then skipped on the wire and older SDKs keep their existing
    /// behavior.
    ///
    /// Keywords are matched case-insensitive against the public
    /// message. When multiple patterns match, the first wins — order
    /// matters, put more specific patterns before generic ones.
    pub fn runbook_url(code: &str, message: &str) -> Option<&'static str> {
        let m = message.to_ascii_lowercase();
        match code {
            "unauthorized" => {
                // Order: put more specific keywords first. "api key
                // required" is a superset of "api key", so the missing-
                // header runbook wins over the invalid-key runbook when
                // the message happens to contain both words.
                if m.contains("api key required") {
                    Some(url("api-key-missing"))
                } else if m.contains("api key") {
                    Some(url("api-key-invalid"))
                } else if m.contains("no active key for agent") {
                    Some(url("agent-not-registered-or-revoked"))
                } else if m.contains("concurrent") || m.contains("rotated concurrently") {
                    Some(url("rotation-race"))
                } else if m.contains("signature") {
                    Some(url("signature-invalid"))
                } else if m.contains("recipient") {
                    Some(url("wrong-recipient"))
                } else {
                    Some(url("unauthorized"))
                }
            }
            "conflict" => {
                if m.contains("nonce") {
                    Some(url("nonce-replay"))
                } else if m.contains("already registered") {
                    Some(url("agent-already-exists"))
                } else if m.contains("rotation") || m.contains("key rotated concurrently") {
                    Some(url("rotation-race"))
                } else {
                    Some(url("conflict"))
                }
            }
            "bad_request" => {
                if m.contains("issued_at") || m.contains("clock skew") {
                    Some(url("clock-skew"))
                } else if m.contains("reachable_at")
                    || m.contains("no endpoints reachable")
                    || m.contains("tunnel_url")
                    || m.contains("did not respond 200")
                {
                    Some(url("endpoint-unreachable"))
                } else if m.contains("nonce") {
                    Some(url("malformed-nonce"))
                } else {
                    None
                }
            }
            "not_found" => {
                if m.contains("agent") {
                    Some(url("agent-not-found"))
                } else if m.contains("transfer") {
                    Some(url("transfer-not-found"))
                } else {
                    None
                }
            }
            "internal_error" => Some(url("internal-error")),
            _ => None,
        }
    }

    /// Build a full runbook URL from a slug. Each slug maps to its
    /// corresponding file under `docs/runbooks/`.
    fn url(slug: &str) -> &'static str {
        match slug {
            "api-key-invalid" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "api-key-invalid.md"
                )
            }
            "api-key-missing" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "api-key-missing.md"
                )
            }
            "agent-already-exists" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "agent-already-exists.md"
                )
            }
            "agent-not-found" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "agent-not-found.md"
                )
            }
            "agent-not-registered-or-revoked" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "agent-not-registered-or-revoked.md"
                )
            }
            "clock-skew" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "clock-skew.md"
                )
            }
            "conflict" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "conflict.md"
                )
            }
            "endpoint-unreachable" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "endpoint-unreachable.md"
                )
            }
            "internal-error" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "internal-error.md"
                )
            }
            "malformed-nonce" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "malformed-nonce.md"
                )
            }
            "nonce-replay" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "nonce-replay.md"
                )
            }
            "rotation-race" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "rotation-race.md"
                )
            }
            "signature-invalid" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "signature-invalid.md"
                )
            }
            "transfer-not-found" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "transfer-not-found.md"
                )
            }
            "unauthorized" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "unauthorized.md"
                )
            }
            "wrong-recipient" => {
                concat!(
                    "https://github.com/icaroholding/aex/blob/master/docs/runbooks/",
                    "wrong-recipient.md"
                )
            }
            _ => "",
        }
    }

    /// Every slug this module knows how to resolve. Used by the
    /// `runbook_files_match_slugs` test below to prove that every
    /// URL we hand out points at a real file on disk.
    #[cfg(test)]
    pub const KNOWN_SLUGS: &[&str] = &[
        "agent-already-exists",
        "agent-not-found",
        "agent-not-registered-or-revoked",
        "api-key-invalid",
        "api-key-missing",
        "clock-skew",
        "conflict",
        "endpoint-unreachable",
        "internal-error",
        "malformed-nonce",
        "nonce-replay",
        "rotation-race",
        "signature-invalid",
        "transfer-not-found",
        "unauthorized",
        "wrong-recipient",
    ];
}

#[derive(Debug)]
pub(crate) struct SimpleError(pub String);
impl std::fmt::Display for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SimpleError {}

#[cfg(test)]
mod tests {
    use super::runbook;
    use std::path::Path;

    #[test]
    fn signature_invalid_message_maps_to_signature_runbook() {
        let url = runbook::runbook_url("unauthorized", "signature does not match challenge")
            .expect("signature messages must have a runbook");
        assert!(url.ends_with("signature-invalid.md"), "got: {url}");
    }

    #[test]
    fn no_active_key_maps_to_agent_not_registered_runbook() {
        let url = runbook::runbook_url(
            "unauthorized",
            "no active key for agent (unregistered or revoked)",
        )
        .expect("no-active-key has a runbook");
        assert!(
            url.ends_with("agent-not-registered-or-revoked.md"),
            "got: {url}"
        );
    }

    #[test]
    fn rotation_race_maps_to_rotation_runbook() {
        let url = runbook::runbook_url(
            "conflict",
            "agent key rotated concurrently; retry with the new current key",
        )
        .expect("rotation race has a runbook");
        assert!(url.ends_with("rotation-race.md"), "got: {url}");
    }

    #[test]
    fn nonce_replay_maps_to_nonce_runbook() {
        let url = runbook::runbook_url("conflict", "nonce already used")
            .expect("nonce replay has a runbook");
        assert!(url.ends_with("nonce-replay.md"), "got: {url}");
    }

    #[test]
    fn duplicate_registration_maps_to_agent_exists_runbook() {
        let url = runbook::runbook_url("conflict", "public_key already registered")
            .expect("duplicate registration has a runbook");
        assert!(url.ends_with("agent-already-exists.md"), "got: {url}");
    }

    #[test]
    fn clock_skew_maps_to_clock_runbook() {
        let url = runbook::runbook_url("bad_request", "issued_at is outside allowed skew (±300s)")
            .expect("clock skew has a runbook");
        assert!(url.ends_with("clock-skew.md"), "got: {url}");
    }

    #[test]
    fn endpoint_unreachable_maps_to_endpoint_runbook() {
        let url = runbook::runbook_url(
            "bad_request",
            "all reachable_at endpoints failed validation (3 entries). First error: ...",
        )
        .expect("unreachable endpoints has a runbook");
        assert!(url.ends_with("endpoint-unreachable.md"), "got: {url}");
    }

    #[test]
    fn api_key_required_maps_to_missing_runbook() {
        let url = runbook::runbook_url("unauthorized", "api key required")
            .expect("api key required has a runbook");
        assert!(url.ends_with("api-key-missing.md"), "got: {url}");
    }

    #[test]
    fn api_key_not_recognized_maps_to_invalid_runbook() {
        let url = runbook::runbook_url("unauthorized", "api key not recognized")
            .expect("api key not recognized has a runbook");
        assert!(url.ends_with("api-key-invalid.md"), "got: {url}");
    }

    #[test]
    fn internal_always_maps_to_internal_runbook() {
        let url = runbook::runbook_url("internal_error", "internal server error")
            .expect("internal errors always have a runbook");
        assert!(url.ends_with("internal-error.md"), "got: {url}");
    }

    #[test]
    fn unknown_code_returns_none() {
        // Forward-compat: a hypothetical new code we don't recognise
        // yet doesn't fabricate a bogus runbook link.
        assert!(runbook::runbook_url("future_code", "anything").is_none());
    }

    #[test]
    fn generic_bad_request_has_no_runbook() {
        // Not every 400 has a specific remediation page — that's fine.
        assert!(runbook::runbook_url("bad_request", "something very specific").is_none());
    }

    /// Invariant: every slug the mapping function hands out must point
    /// at a real file in `docs/runbooks/`. Test fails if a slug is
    /// dropped or a mapping introduces a typo that doesn't match any
    /// existing page.
    #[test]
    fn runbook_files_match_slugs() {
        // The Cargo manifest dir for aex-control-plane is
        // `crates/aex-control-plane/`; runbooks live up two levels
        // at `docs/runbooks/`.
        let runbooks_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/runbooks")
            .canonicalize()
            .expect("docs/runbooks must exist");

        for slug in runbook::KNOWN_SLUGS {
            let file = runbooks_dir.join(format!("{slug}.md"));
            assert!(
                file.exists(),
                "KNOWN_SLUGS contains {slug} but {} does not exist",
                file.display()
            );
        }
    }
}
