//! `aex-data-plane` — sender-side binary that serves one or more blobs
//! behind signed tickets and optionally orchestrates a Cloudflare tunnel
//! so the URL is reachable across the internet.
//!
//! ## Usage (single-blob mode, pre-declared transfer_id)
//!
//! ```
//! export AEX_CONTROL_PLANE_PUBLIC_KEY_HEX=<64 hex chars>
//! export AEX_BLOB_PATH=/tmp/hello.txt
//! export AEX_BLOB_TRANSFER_ID=tx_demo_001
//! export AEX_BLOB_MIME=text/plain
//! aex-data-plane
//! ```
//!
//! ## Usage (admin endpoint for dynamic blob upload)
//!
//! Set `AEX_ADMIN_TOKEN=<random>` to enable `POST /admin/blob/:transfer_id`,
//! which lets an orchestrating script (the sender SDK or a demo runner)
//! push a blob AFTER the control plane assigns a transfer_id.
//!
//! On startup the binary prints `AEX_DATA_PLANE_URL=<public_url>` so
//! orchestrating scripts can capture it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use aex_data_plane::{
    BlobMetadata, BlobSource, DataPlane, DataPlaneConfig, InMemoryBlobSource, TicketVerifier,
};
use aex_scanner::{
    eicar::EicarScanner, injection::RegexInjectionScanner, magic::MagicByteScanner,
    size::SizeLimitScanner, ScanPipeline,
};
use aex_tunnel::{CloudflareQuickTunnel, TunnelProvider};
use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing_subscriber::{prelude::*, EnvFilter};

struct Opts {
    bind_addr: String,
    control_plane_public_key_hex: String,
    tunnel_provider: String,
    cloudflared_binary: Option<String>,
    public_url_override: Option<String>,
    blob_path: Option<PathBuf>,
    blob_transfer_id: Option<String>,
    blob_mime: Option<String>,
    blob_filename: Option<String>,
    max_transfer_bytes: u64,
    admin_token: Option<String>,
}

impl Opts {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            bind_addr: std::env::var("AEX_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:0".into()),
            control_plane_public_key_hex: std::env::var("AEX_CONTROL_PLANE_PUBLIC_KEY_HEX")
                .map_err(|_| "AEX_CONTROL_PLANE_PUBLIC_KEY_HEX is required")?,
            tunnel_provider: std::env::var("AEX_TUNNEL_PROVIDER")
                .unwrap_or_else(|_| "cloudflare".into()),
            cloudflared_binary: std::env::var("AEX_CLOUDFLARED_BINARY").ok(),
            public_url_override: std::env::var("AEX_PUBLIC_URL").ok(),
            blob_path: std::env::var("AEX_BLOB_PATH").ok().map(PathBuf::from),
            blob_transfer_id: std::env::var("AEX_BLOB_TRANSFER_ID").ok(),
            blob_mime: std::env::var("AEX_BLOB_MIME").ok(),
            blob_filename: std::env::var("AEX_BLOB_FILENAME").ok(),
            max_transfer_bytes: std::env::var("AEX_MAX_TRANSFER_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100 * 1024 * 1024),
            admin_token: std::env::var("AEX_ADMIN_TOKEN")
                .ok()
                .filter(|s| !s.is_empty()),
        })
    }
}

#[derive(Clone)]
struct AdminState {
    source: Arc<InMemoryBlobSource>,
    token: String,
}

#[derive(Debug, Deserialize)]
struct AdminInsertQuery {
    mime: Option<String>,
    filename: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_tracing();

    let opts = Opts::from_env()?;

    let listener = TcpListener::bind(&opts.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(%local_addr, "aex-data-plane listener bound");

    let (public_url, _tunnel_guard) = resolve_public_url(&opts, local_addr.port()).await?;
    tracing::info!(%public_url, "public URL resolved");

    let shared_source = load_blob_source(&opts).await?;

    let cp_pubkey_bytes: [u8; 32] = hex::decode(&opts.control_plane_public_key_hex)?
        .try_into()
        .map_err(|_| "AEX_CONTROL_PLANE_PUBLIC_KEY_HEX must decode to 32 bytes")?;
    let cp_pubkey = VerifyingKey::from_bytes(&cp_pubkey_bytes)?;
    let verifier = Arc::new(TicketVerifier::new(cp_pubkey, public_url.clone()));

    let scanner = Arc::new(
        ScanPipeline::new()
            .with_scanner(Arc::new(SizeLimitScanner::new(opts.max_transfer_bytes)))
            .with_scanner(Arc::new(MagicByteScanner::new()))
            .with_scanner(Arc::new(EicarScanner::new()))
            .with_scanner(Arc::new(RegexInjectionScanner::new())),
    );

    let dp = DataPlane::new(DataPlaneConfig {
        blob_source: shared_source.clone() as Arc<dyn BlobSource>,
        ticket_verifier: verifier,
        scanner: Some(scanner),
        scan_cache: Arc::new(RwLock::new(HashMap::new())),
    });

    let mut app = dp.router();
    if let Some(token) = opts.admin_token.clone() {
        let admin: Router<()> = Router::new()
            .route("/admin/blob/:transfer_id", post(admin_insert_blob))
            .with_state(AdminState {
                source: shared_source.clone(),
                token,
            });
        app = app.merge(admin);
        tracing::warn!(
            "admin endpoint enabled at POST /admin/blob/:transfer_id — token-auth only, \
             never expose this port to the public internet without a firewall"
        );
    }

    // Machine-readable line for orchestrating scripts (e.g. demo runner).
    println!("AEX_DATA_PLANE_URL={}", public_url);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn admin_insert_blob(
    State(st): State<AdminState>,
    Path(transfer_id): Path<String>,
    Query(q): Query<AdminInsertQuery>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let provided = headers
        .get("x-aex-admin-token")
        .and_then(|v| v.to_str().ok());
    if provided != Some(st.token.as_str()) {
        return (StatusCode::UNAUTHORIZED, "bad admin token").into_response();
    }
    let metadata = BlobMetadata {
        size: body.len() as u64,
        mime: q.mime.unwrap_or_else(|| "application/octet-stream".into()),
        filename: q.filename.unwrap_or_else(|| "blob".into()),
    };
    st.source
        .insert(transfer_id.clone(), metadata, body.to_vec())
        .await;
    tracing::info!(%transfer_id, size = body.len(), "admin inserted blob");
    (StatusCode::CREATED, "ok").into_response()
}

async fn resolve_public_url(
    opts: &Opts,
    local_port: u16,
) -> Result<(String, Option<CloudflareQuickTunnel>), Box<dyn std::error::Error>> {
    match opts.tunnel_provider.as_str() {
        "none" => {
            let url = opts
                .public_url_override
                .clone()
                .ok_or("AEX_PUBLIC_URL is required when AEX_TUNNEL_PROVIDER=none")?;
            Ok((url, None))
        }
        "cloudflare" => {
            let mut t = CloudflareQuickTunnel::new();
            if let Some(p) = &opts.cloudflared_binary {
                t = t.with_binary_path(p);
            }
            t.start(local_port).await?;
            let url = t
                .public_url()
                .ok_or("cloudflared returned no URL despite connecting")?;
            Ok((url, Some(t)))
        }
        other => Err(format!(
            "unknown AEX_TUNNEL_PROVIDER={} (expected 'cloudflare' or 'none')",
            other
        )
        .into()),
    }
}

async fn load_blob_source(
    opts: &Opts,
) -> Result<Arc<InMemoryBlobSource>, Box<dyn std::error::Error>> {
    let source = Arc::new(InMemoryBlobSource::new());

    if let Some(blob_path) = &opts.blob_path {
        let transfer_id = opts
            .blob_transfer_id
            .clone()
            .ok_or("AEX_BLOB_TRANSFER_ID is required when AEX_BLOB_PATH is set")?;
        let bytes = tokio::fs::read(blob_path).await?;
        let mime = opts
            .blob_mime
            .clone()
            .unwrap_or_else(|| "application/octet-stream".into());
        let filename = opts.blob_filename.clone().unwrap_or_else(|| {
            blob_path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "blob".into())
        });
        let metadata = BlobMetadata {
            size: bytes.len() as u64,
            mime,
            filename,
        };
        source.insert(transfer_id.clone(), metadata, bytes).await;
        tracing::info!(%transfer_id, path = %blob_path.display(), "preloaded blob");
    }

    Ok(source)
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,aex_data_plane=debug,aex_tunnel=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();
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
