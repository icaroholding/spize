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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::Internal(ref err) = self {
            tracing::error!(error = %err, "internal error serving request");
        }
        let status = self.status();
        let body = ErrorBody {
            code: self.code(),
            message: self.public_message(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<aex_core::Error> for ApiError {
    fn from(err: aex_core::Error) -> Self {
        use aex_core::Error::*;
        match err {
            InvalidAgentId(m) => ApiError::BadRequest(format!("invalid agent_id: {}", m)),
            UnknownIdentityScheme => {
                ApiError::BadRequest("unknown identity scheme".into())
            }
            SignatureInvalid => {
                ApiError::Unauthorized("signature verification failed".into())
            }
            SignatureFormat(m) => ApiError::BadRequest(format!("bad signature: {}", m)),
            KeyUnavailable(m) => ApiError::Internal(Box::new(SimpleError(format!(
                "key unavailable: {}",
                m
            )))),
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

#[derive(Debug)]
pub(crate) struct SimpleError(pub String);
impl std::fmt::Display for SimpleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for SimpleError {}
