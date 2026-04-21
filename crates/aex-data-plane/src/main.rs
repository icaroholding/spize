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
//! ## Readiness invariant
//!
//! Orchestrators MUST wait for the binary to emit BOTH
//!
//! ```text
//! AEX_DATA_PLANE_URL=<public_url>
//! AEX_READY=1
//! ```
//!
//! on stdout before treating the data plane as usable. `AEX_READY=1`
//! is only emitted after the binary has verified locally that:
//!
//! 1. DNS for the tunnel's hostname resolves publicly — proves the
//!    Cloudflare edge has actually published the quick-tunnel record.
//! 2. A TCP connection to `:443` on one of the resolved addresses
//!    succeeds — proves the edge is accepting connections for this
//!    tunnel.
//!
//! The binary intentionally does NOT do a full HTTP round-trip against
//! its own tunnel: doing so is surprisingly brittle (TLS client quirks,
//! DNS cache layering), and it is the control plane's job, not the
//! data plane's, to prove end-to-end HTTP reachability before issuing
//! tickets against a tunnel_url. See `aex-control-plane` for that
//! check.

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

/// Upper bound for the tunnel's DNS record to appear in public DNS
/// after `cloudflared` reports "connected". Typical observed time is
/// 5-30s; we allow headroom for slow networks. Negotiable via
/// `AEX_READINESS_TIMEOUT_SECS`.
const DEFAULT_READINESS_TIMEOUT_SECS: u64 = 60;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI pre-pass: --help, --version, --version --verbose short-circuit
    // before any env / tracing setup so they work in any environment.
    match parse_cli(std::env::args().skip(1)) {
        CliAction::PrintHelp => {
            print_help();
            return Ok(());
        }
        CliAction::PrintVersion { verbose } => {
            print_version(verbose);
            return Ok(());
        }
        CliAction::Run => {}
    }

    init_tracing();

    let opts = Opts::from_env()?;
    let readiness_timeout = std::env::var("AEX_READINESS_TIMEOUT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_READINESS_TIMEOUT_SECS);

    // Kick off the captive-portal probe in parallel with tunnel startup.
    // It emits `AEX_NETWORK_STATE=<state>` on stdout when the consensus
    // of Apple/Google/MS NCSI probes completes (protocol-v1 §5.3). The
    // probe never fails; worst case it emits `unknown`. Advisory only —
    // orchestrators use it to surface captive-portal conditions to end
    // users but never gate execution on it.
    tokio::spawn(async {
        emit_network_state().await;
    });

    let listener = TcpListener::bind(&opts.bind_addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(%local_addr, "aex-data-plane listener bound");

    let (public_url, tunnel_guard) = resolve_public_url(&opts, local_addr.port()).await?;
    tracing::info!(%public_url, "tunnel reports connected; waiting for public reachability");

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

    // Spawn the server immediately so the tunnel has something to talk
    // to when it finishes propagating in public DNS. We will join this
    // task at the bottom.
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
    });

    // Self-verify that a full external round-trip (DNS → Cloudflare
    // edge → our process) works. Any orchestrator downstream — the
    // demo, the desktop, a hosted deployer — then only has to watch
    // stdout for `AEX_READY=1`.
    if let Err(err) = verify_tunnel_reachable(&public_url, readiness_timeout).await {
        tracing::error!(error = %err, "tunnel failed self-roundtrip — refusing to advertise URL");
        server_handle.abort();
        drop(tunnel_guard);
        return Err(err);
    }

    // Order matters: URL first, then READY. Orchestrators parse both.
    println!("AEX_DATA_PLANE_URL={}", public_url);
    println!("AEX_READY=1");
    tracing::info!(%public_url, "data plane ready");

    match server_handle.await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e.into()),
        Err(join_err) => Err(Box::new(join_err)),
    }
}

/// Wait until the tunnel's hostname resolves publicly AND TCP:443
/// accepts a connection on at least one resolved address. Deliberately
/// avoids HTTP/TLS so this is not coupled to any one client library's
/// quirks — the HTTP-level healthcheck lives in the control plane.
///
/// Uses a hickory resolver talking directly to 1.1.1.1, bypassing the
/// OS resolver (which on macOS caches NXDOMAIN for ~60s and would
/// sabotage retries during the tunnel's DNS-propagation window).
async fn verify_tunnel_reachable(
    public_url: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    use hickory_resolver::config::{ResolverConfig, ResolverOpts};
    use hickory_resolver::TokioAsyncResolver;

    let parsed = url::Url::parse(public_url)?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("public URL {public_url} has no host component"))?
        .to_string();
    let port = parsed.port().unwrap_or(443);

    let mut resolver_opts = ResolverOpts::default();
    // Defeat any built-in positive cache so a fresh lookup happens each
    // time. We're not worried about traffic — this runs a handful of
    // times in a startup window.
    resolver_opts.cache_size = 0;
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), resolver_opts);

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    let mut attempt: u32 = 0;
    let mut last_err: String = "no attempts made".into();

    while tokio::time::Instant::now() < deadline {
        attempt += 1;

        // Step 1: resolve DNS via 1.1.1.1 directly. Bypasses the OS
        // negative cache entirely.
        let addrs: Vec<std::net::SocketAddr> = match resolver.lookup_ip(host.as_str()).await {
            Ok(r) => r
                .iter()
                .map(|ip| std::net::SocketAddr::new(ip, port))
                .collect(),
            Err(e) => {
                last_err = format!("dns: {e}");
                tracing::debug!(attempt, err = %last_err, "tunnel readiness: DNS not resolving");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                continue;
            }
        };
        if addrs.is_empty() {
            last_err = "dns: empty address list".into();
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            continue;
        }

        // Step 2: TCP connect on the first resolved address. Succeeds
        // the moment the Cloudflare edge accepts SYN for this tunnel.
        let addr = addrs[0];
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(addr),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                tracing::info!(attempt, %host, %addr, "tunnel reachable (DNS + TCP)");
                return Ok(());
            }
            Ok(Err(e)) => {
                last_err = format!("tcp connect {addr}: {e}");
            }
            Err(_) => {
                last_err = format!("tcp connect {addr}: 5s timeout");
            }
        }
        tracing::debug!(attempt, err = %last_err, "tunnel readiness: TCP not accepting");
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    Err(format!(
        "tunnel {public_url} did not pass DNS+TCP readiness within {timeout_secs}s \
         after {attempt} attempts (last error: {last_err}). Either the Cloudflare \
         quick-tunnel record never propagated into public DNS, or this host cannot \
         reach the Cloudflare edge on port 443."
    )
    .into())
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

/// Action dispatched from the first-pass CLI parse.
enum CliAction {
    Run,
    PrintVersion { verbose: bool },
    PrintHelp,
}

/// Parse the minimal flag set this binary accepts. Anything else is
/// ignored so env-driven invocations remain compatible.
fn parse_cli(args: impl Iterator<Item = String>) -> CliAction {
    let args: Vec<String> = args.collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return CliAction::PrintHelp;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");
        return CliAction::PrintVersion { verbose };
    }
    CliAction::Run
}

fn print_help() {
    println!(
        "aex-data-plane {} — sender-side data plane for the AEX protocol.\n\
         \n\
         USAGE:\n    \
             aex-data-plane [FLAGS]\n\
         \n\
         FLAGS:\n    \
             -h, --help       Print this help and exit.\n    \
             -V, --version    Print version and exit.\n    \
             -v, --verbose    With --version: also print compiled-in transports and DNS config.\n\
         \n\
         With no flags, the binary is controlled by environment variables — see\n\
         the docstring at the top of src/main.rs (`cargo doc -p aex-data-plane`)\n\
         for the full list. Common ones:\n\
         \n    \
             AEX_CONTROL_PLANE_PUBLIC_KEY_HEX  (required) 64-hex control-plane signing key\n    \
             AEX_TUNNEL_PROVIDER                cloudflare | none     (default: cloudflare)\n    \
             AEX_BLOB_PATH                      pre-load a blob from disk\n    \
             AEX_ADMIN_TOKEN                    enable POST /admin/blob/:id for orchestrators\n",
        env!("CARGO_PKG_VERSION")
    );
}

fn print_version(verbose: bool) {
    println!("aex-data-plane {}", env!("CARGO_PKG_VERSION"));
    if !verbose {
        return;
    }
    println!();
    println!("Compiled-in tunnel providers:");
    println!("  cloudflare  Cloudflare Quick Tunnels, orchestrated via `cloudflared`.");
    println!("  none        No tunnel; AEX_PUBLIC_URL must be supplied.");
    println!();
    println!("DNS:");
    println!("  Readiness probe resolver  hickory-resolver via Cloudflare 1.1.1.1 / 1.0.0.1");
    println!("                            (cache_size=0, ndots=1; bypasses OS resolv.conf)");
    println!("  Network-state probes      DoH via aex-net (protocol-v1 §5.3)");
    println!();
    println!("Repository: {}", env!("CARGO_PKG_REPOSITORY"));
}

/// Run the captive-portal probe consensus once and emit
/// `AEX_NETWORK_STATE=<state>` on stdout per protocol-v1 §5.3.
async fn emit_network_state() {
    let client = match aex_net::build_http_client_with_timeout(
        "data-plane-captive",
        std::time::Duration::from_secs(6),
    ) {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "captive probe http client init failed");
            println!("AEX_NETWORK_STATE=unknown");
            return;
        }
    };
    let state = aex_net::detect_network_state(&client).await;
    println!("AEX_NETWORK_STATE={}", state.as_stdout_value());
    tracing::info!(state = state.as_stdout_value(), "captive-portal probe done");
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
