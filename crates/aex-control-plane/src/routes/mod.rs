pub mod agents;
pub mod health;
pub mod inbox;
pub mod metrics;
pub mod transfers;

use axum::Router;

use crate::AppState;

pub fn v1_router() -> Router<AppState> {
    Router::new()
        .nest("/agents", agents::router())
        .nest("/transfers", transfers::router())
        .merge(inbox::router())
}
