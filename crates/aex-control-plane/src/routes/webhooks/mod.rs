//! Inbound webhook endpoints (Sprint 4 PR 6).
//!
//! Webhooks sit OUTSIDE `/v1/*` because their auth model is totally
//! different: instead of an admin bearer token or an api_key, each
//! provider signs the payload with a shared secret we verify
//! per-request. Separating the route tree keeps the admin/customer
//! auth concerns cleanly isolated.

pub mod stripe;

use axum::Router;

use crate::AppState;

pub fn router() -> Router<AppState> {
    Router::new().nest("/stripe", stripe::router())
}
