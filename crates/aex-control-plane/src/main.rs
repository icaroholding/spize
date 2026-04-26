use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing_subscriber::{prelude::*, EnvFilter};

use aex_audit::FileAuditLog;
use aex_control_plane::{
    blob::FileBlobStore,
    build_app_with_cors,
    clock::SystemClock,
    config::Config,
    endpoint_validator::EndpointValidator,
    health_monitor::{HealthMonitor, ValidatorProber},
    signer::ControlPlaneSigner,
    AppState,
};
use aex_policy::{TierName, TierPolicy};
use aex_scanner::{
    eicar::EicarScanner, injection::RegexInjectionScanner, magic::MagicByteScanner,
    size::SizeLimitScanner, ScanPipeline,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let cfg = Config::from_env()?;
    tracing::info!(bind = %cfg.bind_addr, "aex-control-plane starting");

    let db = PgPoolOptions::new()
        .max_connections(16)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await?;

    sqlx::migrate!("./migrations").run(&db).await?;
    tracing::info!("database migrations applied");

    // Default production wiring. Each of these is pluggable — production
    // deployments swap them via alternative constructors.
    let scanner = ScanPipeline::new()
        .with_scanner(Arc::new(SizeLimitScanner::new(cfg.max_transfer_bytes)))
        .with_scanner(Arc::new(MagicByteScanner::new()))
        .with_scanner(Arc::new(EicarScanner::new()))
        .with_scanner(Arc::new(RegexInjectionScanner::new()));

    let policy = Arc::new(TierPolicy::for_tier(TierName::Dev));

    let audit = Arc::new(FileAuditLog::open(&cfg.audit_log_path).await?);
    tracing::info!(path = %cfg.audit_log_path.display(), "audit log opened");

    let blobs = Arc::new(FileBlobStore::new(&cfg.blob_dir).await?);
    tracing::info!(dir = %cfg.blob_dir.display(), "blob store ready");

    let signer = Arc::new(ControlPlaneSigner::load_or_generate(&cfg.signing_key_path).await?);
    tracing::info!(
        pub_key = %signer.public_key_hex(),
        path = %cfg.signing_key_path.display(),
        "control-plane signing key ready"
    );

    let mut state = AppState::new(db.clone(), scanner, policy, audit, blobs).with_signer(signer);
    if let Some(token) = cfg.admin_token.clone() {
        tracing::info!(
            "admin endpoints enabled; presenting Bearer {}... opens /v1/admin/*",
            &token[..token.len().min(6)]
        );
        state = state.with_admin_token(token);
    } else {
        tracing::warn!(
            "AEX_ADMIN_TOKEN is not set; /v1/admin/* endpoints will return 503. \
             Generate with `openssl rand -hex 16` and restart."
        );
    }
    state = state
        .with_stripe(cfg.stripe.clone())
        .with_customer_auth(cfg.customer_auth.clone())
        .with_email(cfg.email.clone());
    let metrics_for_monitor = state.metrics.clone();
    let app = build_app_with_cors(state, &cfg.cors_allowed_origins);

    // Sprint 3: background endpoint health loop (ADR-0014 + ADR-0021).
    // The monitor owns its own copy of the DB pool + validator so it
    // never contends with axum handlers for permits beyond the
    // process-wide EndpointValidator semaphore. It shares the
    // AppState metrics registry so `/metrics` sees probe outcomes
    // and state transitions alongside the HTTP-emitted counters.
    let prober = Arc::new(ValidatorProber::new(EndpointValidator::with_defaults()));
    let monitor_handle = HealthMonitor::spawn(
        db,
        prober,
        Arc::new(SystemClock::new()),
        metrics_for_monitor,
    );

    let listener = TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    // Ctrl+C / SIGTERM arrived — stop the monitor BEFORE returning so
    // the Tokio runtime doesn't drop mid-tick and leave the DB pool
    // in an awkward state.
    if let Err(e) = monitor_handle.shutdown().await {
        tracing::warn!(error = %e, "health monitor shutdown join error");
    }

    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,aex_control_plane=debug,sqlx=warn"));
    let json = matches!(std::env::var("LOG_FORMAT").as_deref(), Ok("json"));
    let registry = tracing_subscriber::registry().with(filter);
    if json {
        registry
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_target(true)
                    .with_current_span(true),
            )
            .init();
    } else {
        registry
            .with(tracing_subscriber::fmt::layer().with_target(true))
            .init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}
