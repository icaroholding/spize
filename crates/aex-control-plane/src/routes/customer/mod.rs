//! Customer-facing dashboard surface (Sprint 4 PR 7).
//!
//! Routes under `/v1/customer/*` are the backend for the customer
//! dashboard SPA. Authentication is via session cookie (issued by
//! the magic-link verify endpoint; validated by
//! [`auth::require_customer_session`] middleware).
//!
//! - `/v1/customer/auth/magic-link/request` — public; takes an
//!   email, mints a single-use token, mails the link.
//! - `/v1/customer/auth/magic-link/verify` — public; redeems a
//!   token + sets the session cookie.
//! - `/v1/customer/auth/whoami` — authenticated; echo session.
//! - `/v1/customer/auth/logout` — clears the cookie.
//! - `/v1/customer/api-keys` (POST/GET) — authenticated; mint and
//!   list the customer's own keys.
//! - `/v1/customer/api-keys/:id` (DELETE) — authenticated; revoke
//!   a key the customer owns. Cross-customer revoke is 404.

pub mod api_keys;
pub mod auth;

use axum::{middleware, Router};

use crate::AppState;

pub fn router(state: AppState) -> Router<AppState> {
    // Authenticated subtree — wrapped in the session middleware so
    // every endpoint here transparently sees CustomerSession via
    // request extensions.
    let authed = Router::new()
        .merge(auth::authed_router())
        .merge(api_keys::router())
        .route_layer(middleware::from_fn_with_state(
            state,
            auth::require_customer_session,
        ));

    Router::new().merge(auth::public_router()).merge(authed)
}
