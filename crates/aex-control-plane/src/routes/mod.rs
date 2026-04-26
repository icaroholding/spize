pub mod admin;
pub mod agents;
pub mod customer;
pub mod health;
pub mod inbox;
pub mod metered;
pub mod metrics;
pub mod transfers;
pub mod webhooks;

use axum::{middleware, Router};

use crate::AppState;

pub fn v1_router(state: AppState) -> Router<AppState> {
    // Admin subtree is wrapped in the bearer-token middleware here
    // rather than in the admin module itself so every new admin
    // endpoint automatically inherits the gate.
    let admin = admin::router().route_layer(middleware::from_fn_with_state(
        state.clone(),
        admin::require_admin_token,
    ));

    // Metered subtree authenticates callers by API key. Future
    // quota-enforced endpoints land here and automatically inherit
    // the auth middleware without further wiring.
    let metered = metered::router().route_layer(middleware::from_fn_with_state(
        state.clone(),
        metered::require_api_key,
    ));

    // Customer dashboard subtree. Internal split between public
    // (magic-link request/verify) and authenticated (whoami,
    // logout, api-keys CRUD) is owned by `customer::router`.
    let customer = customer::router(state);

    Router::new()
        .nest("/agents", agents::router())
        .nest("/transfers", transfers::router())
        .nest("/admin", admin)
        .nest("/metered", metered)
        .nest("/customer", customer)
        .merge(inbox::router())
}
