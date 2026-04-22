//! Agent Exchange Protocol (AEX) control plane.
//!
//! The control plane coordinates transfers (identity, routing, policy,
//! scanner verdicts, audit). In M1 the control plane also holds uploaded
//! bytes long enough to scan + serve; from Phase D onward that role moves
//! to a Cloudflare-tunnelled data plane and this crate only coordinates.
//!
//! [`build_app`] is the axum entry point: it takes a fully-migrated
//! [`sqlx::PgPool`] and a composed [`AppState`] and returns a [`Router`]
//! ready to serve.

pub mod blob;
pub mod clock;
pub mod config;
pub mod db;
pub mod endpoint_validator;
pub mod error;
pub mod routes;
pub mod signer;
pub mod verify;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use aex_audit::AuditLog;
use aex_policy::PolicyEngine;
use aex_scanner::ScanPipeline;

use crate::blob::BlobStore;
use crate::clock::{Clock, SystemClock};
use crate::endpoint_validator::EndpointValidator;

/// Application state shared across all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub scanner: Arc<ScanPipeline>,
    pub policy: Arc<dyn PolicyEngine>,
    pub audit: Arc<dyn AuditLog>,
    pub blobs: Arc<dyn BlobStore>,
    pub signer: Option<Arc<signer::ControlPlaneSigner>>,
    pub endpoint_validator: EndpointValidator,
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    pub fn new(
        db: PgPool,
        scanner: ScanPipeline,
        policy: Arc<dyn PolicyEngine>,
        audit: Arc<dyn AuditLog>,
        blobs: Arc<dyn BlobStore>,
    ) -> Self {
        Self {
            db,
            scanner: Arc::new(scanner),
            policy,
            audit,
            blobs,
            signer: None,
            endpoint_validator: EndpointValidator::with_defaults(),
            clock: Arc::new(SystemClock::new()),
        }
    }

    pub fn with_signer(mut self, signer: Arc<signer::ControlPlaneSigner>) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Override the endpoint validator (tests use shorter budgets / smaller pools).
    pub fn with_endpoint_validator(mut self, validator: EndpointValidator) -> Self {
        self.endpoint_validator = validator;
        self
    }

    /// Override the clock (tests use [`crate::clock::FrozenClock`] to step
    /// across the rotation grace-period boundary deterministically).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }
}

/// Body limit for upload requests. Tier policies enforce per-tier caps
/// but we apply a hard ceiling at the transport layer too so a flooded
/// pipe can't OOM the server before business rules run.
const MAX_UPLOAD_BODY_BYTES: usize = 500 * 1024 * 1024;

/// Build a [`CorsLayer`] from a comma-separated list of allowed origins.
/// An empty list produces a no-op layer (same-origin only). `*` is allowed
/// but flagged in the log so operators see they're running wide-open.
fn build_cors_layer(allowed: &[String]) -> CorsLayer {
    if allowed.is_empty() {
        return CorsLayer::new();
    }
    if allowed.iter().any(|o| o == "*") {
        tracing::warn!(
            "CORS_ALLOWED_ORIGINS=* — any origin may call the control plane. \
             Set CORS_ALLOWED_ORIGINS to a comma-separated allowlist in production."
        );
        return CorsLayer::new()
            .allow_origin(AllowOrigin::any())
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([header::CONTENT_TYPE]);
    }
    let origins: Vec<HeaderValue> = allowed
        .iter()
        .filter_map(|o| HeaderValue::from_str(o).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE])
}

pub fn build_app(state: AppState) -> Router {
    build_app_with_cors(state, &[])
}

pub fn build_app_with_cors(state: AppState, cors_origins: &[String]) -> Router {
    Router::new()
        .merge(routes::health::router())
        .nest("/v1", routes::v1_router())
        .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_BODY_BYTES))
        .layer(build_cors_layer(cors_origins))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(60)))
        .with_state(state)
}
