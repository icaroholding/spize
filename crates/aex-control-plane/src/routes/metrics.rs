//! `GET /metrics` — Prometheus exposition endpoint (Sprint 3).
//!
//! Mounted at the root (not under `/v1/`) so Prometheus scrape configs
//! can use the conventional path without a prefix. Response
//! `Content-Type` is the Prometheus text exposition format
//! (`text/plain; version=0.0.4`) which every scraper recognises.

use axum::{extract::State, http::header, response::IntoResponse, routing::get, Router};

use crate::AppState;

/// Prometheus text exposition format content-type header value.
const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render();
    ([(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)], body)
}

pub fn router() -> Router<AppState> {
    Router::new().route("/metrics", get(metrics))
}
