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
//!
//! Downstream consumers (e.g. the private `spize-cp` overlay) compose
//! a wider router by calling [`public_routes`] for the protocol surface,
//! merging their own commercial routes on top, and applying the shared
//! middleware stack via [`build_cors_layer`] + [`MAX_UPLOAD_BODY_BYTES`].

pub mod blob;
pub mod clock;
pub mod config;
pub mod db;
pub mod endpoint_validator;
pub mod error;
pub mod health_monitor;
pub mod metrics;
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
///
/// Public so downstream consumers (overlay control planes that wrap
/// this crate) can apply the same hard ceiling on their merged
/// router.
pub const MAX_UPLOAD_BODY_BYTES: usize = 500 * 1024 * 1024;

/// Build a [`CorsLayer`] from a comma-separated list of allowed origins.
/// An empty list produces a no-op layer (same-origin only). `*` is allowed
/// but flagged in the log so operators see they're running wide-open.
///
/// On the **allowlist** branch (the production path), the layer also
/// emits `Access-Control-Allow-Credentials: true`. The customer
/// dashboard at `https://spize.io` calls `https://api.spize.io` with
/// `fetch(..., { credentials: "include" })` to send the
/// `aex_session` cookie cross-subdomain — without that header the
/// browser drops the cookie and the dashboard can't authenticate.
///
/// We deliberately do NOT enable credentials on the wildcard (`*`)
/// branch: the CORS spec forbids combining `Allow-Credentials: true`
/// with `Allow-Origin: *`, and browsers reject such responses.
/// Wildcard remains a developer-only escape hatch — production
/// must use an explicit allowlist.
pub fn build_cors_layer(allowed: &[String]) -> CorsLayer {
    if allowed.is_empty() {
        return CorsLayer::new();
    }
    if allowed.iter().any(|o| o == "*") {
        tracing::warn!(
            "CORS_ALLOWED_ORIGINS=* — any origin may call the control plane. \
             Set CORS_ALLOWED_ORIGINS to a comma-separated allowlist in production. \
             Note: credentials (cookies) are NOT allowed in this mode — the browser \
             rejects `Allow-Credentials: true` with `Allow-Origin: *`."
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
        // The dashboard (spize.io → api.spize.io) needs the cookie
        // cross-subdomain. See module-level comment above.
        .allow_credentials(true)
}

/// Build the public protocol routes (health, metrics, /v1) with the
/// supplied state baked in. No transport-layer middleware applied —
/// callers add layers on the merged router so a single CORS / body-
/// limit configuration covers both public and any commercial
/// overlay routes.
pub fn public_routes(state: AppState) -> Router {
    Router::new()
        .merge(routes::health::router())
        .merge(routes::metrics::router())
        .nest("/v1", routes::v1_router(state.clone()))
        .with_state(state)
}

/// Run the control plane's embedded migrations against `pool`.
/// Public so the private `spize-cp` overlay can boot the full
/// public schema before applying its own commercial migrations.
pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!("./migrations").run(pool).await
}

pub fn build_app(state: AppState) -> Router {
    build_app_with_cors(state, &[])
}

pub fn build_app_with_cors(state: AppState, cors_origins: &[String]) -> Router {
    public_routes(state)
        .layer(RequestBodyLimitLayer::new(MAX_UPLOAD_BODY_BYTES))
        .layer(build_cors_layer(cors_origins))
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(60)))
}

#[cfg(test)]
mod cors_tests {
    use super::build_cors_layer;
    use axum::http::{header, HeaderValue, Method, Request, StatusCode};
    use axum::{routing::post, Router};
    use tower::ServiceExt;

    /// CORS preflight against an allowlisted origin must echo
    /// `Access-Control-Allow-Credentials: true`. Downstream
    /// dashboards rely on cross-subdomain `fetch(..., {credentials:
    /// "include"})` calls — silently dropping the header here would
    /// break their session cookie path.
    #[tokio::test]
    async fn allowlist_preflight_emits_allow_credentials() {
        let app = Router::new()
            .route("/v1/admin/whoami", post(|| async { "ok" }))
            .layer(build_cors_layer(&[
                "https://spize.io".into(),
                "https://www.spize.io".into(),
            ]));

        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/v1/admin/whoami")
            .header(header::ORIGIN, "https://spize.io")
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://spize.io"))
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS),
            Some(&HeaderValue::from_static("true")),
            "allowlist branch must emit Access-Control-Allow-Credentials: true"
        );
    }

    /// Wildcard (`*`) branch must NOT emit `Allow-Credentials: true`
    /// because browsers reject the combination per CORS spec. This
    /// test guards against an accidental future change that would
    /// silently break the wildcard fallback.
    #[tokio::test]
    async fn wildcard_branch_does_not_emit_allow_credentials() {
        let app = Router::new()
            .route("/x", post(|| async { "ok" }))
            .layer(build_cors_layer(&["*".into()]));

        let req = Request::builder()
            .method(Method::OPTIONS)
            .uri("/x")
            .header(header::ORIGIN, "https://anywhere.example")
            .header("access-control-request-method", "POST")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_none(),
            "wildcard branch must NOT set Allow-Credentials (browser would reject)"
        );
    }
}
