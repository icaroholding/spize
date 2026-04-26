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
pub mod email;
pub mod endpoint_validator;
pub mod error;
pub mod health_monitor;
pub mod metrics;
pub mod routes;
pub mod session;
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
use crate::config::{CustomerAuthConfig, EmailConfig, StripeConfig};
use crate::endpoint_validator::EndpointValidator;
use crate::metrics::Metrics;

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
    pub metrics: Metrics,
    /// Shared-secret bearer token gating `/v1/admin/*`. When `None`,
    /// the admin middleware returns 503 on every admin request — see
    /// `routes::admin::require_admin_token`.
    pub admin_token: Option<String>,
    /// Stripe webhook config (signing secret + price→tier map).
    /// When the secret is `None` the webhook handler short-circuits
    /// with 503 instead of silently 404'ing — same philosophy as
    /// `admin_token`.
    pub stripe: StripeConfig,
    /// Customer dashboard / magic-link auth config (Sprint 4 PR 7).
    pub customer_auth: CustomerAuthConfig,
    /// Resend transactional-email config — magic-link delivery.
    /// Optional: when missing the magic-link request returns the
    /// token in the response body (dev-only convenience).
    pub email: EmailConfig,
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
            metrics: Metrics::new(),
            admin_token: None,
            stripe: StripeConfig::default(),
            customer_auth: CustomerAuthConfig::default(),
            email: EmailConfig::default(),
        }
    }

    /// Set the shared-secret bearer token gating `/v1/admin/*`. Test
    /// harnesses call this to exercise the admin middleware against
    /// a known token; production wiring plumbs the value from
    /// `Config::admin_token`.
    pub fn with_admin_token(mut self, token: impl Into<String>) -> Self {
        self.admin_token = Some(token.into());
        self
    }

    /// Install Stripe webhook config (secret + price→tier map).
    /// Tests override this to exercise the webhook against a known
    /// secret + fake price IDs; production wiring plumbs the value
    /// from `Config::stripe`.
    pub fn with_stripe(mut self, stripe: StripeConfig) -> Self {
        self.stripe = stripe;
        self
    }

    /// Install customer-auth config (JWT secret + frontend URL).
    pub fn with_customer_auth(mut self, customer_auth: CustomerAuthConfig) -> Self {
        self.customer_auth = customer_auth;
        self
    }

    /// Install email config (Resend API key + From address).
    pub fn with_email(mut self, email: EmailConfig) -> Self {
        self.email = email;
        self
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
        .merge(routes::metrics::router())
        .nest("/v1", routes::v1_router(state.clone()))
        // Webhooks live outside /v1 and have no shared auth —
        // per-provider signature verification happens inside each
        // handler.
        .nest("/webhooks", routes::webhooks::router())
        .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_BODY_BYTES))
        .layer(build_cors_layer(cors_origins))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(60)))
        .with_state(state)
}
