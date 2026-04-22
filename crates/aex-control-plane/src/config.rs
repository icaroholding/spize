//! Environment-driven configuration.
//!
//! The control plane takes everything from env vars. No config files, no
//! flags. This keeps deployments (Fly.io, Render, k8s) simple and makes the
//! binary a pure 12-factor service.

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use thiserror::Error;

const DEFAULT_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_AUDIT_LOG_PATH: &str = "./data/audit.jsonl";
const DEFAULT_BLOB_DIR: &str = "./data/blobs";
const DEFAULT_SIGNING_KEY_PATH: &str = "./data/signing-key.bin";
/// Default hard size cap fed to the size-limit scanner. Individual tier
/// policies apply their own (typically lower) caps; this is the absolute
/// ceiling above which the server refuses the request before even
/// touching the policy layer.
const DEFAULT_MAX_TRANSFER_BYTES: u64 = 500 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("env var {0} is required but was not set")]
    Missing(&'static str),

    #[error("env var {name} is invalid: {msg}")]
    Invalid { name: &'static str, msg: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub bind_addr: SocketAddr,
    pub audit_log_path: PathBuf,
    pub blob_dir: PathBuf,
    pub signing_key_path: PathBuf,
    pub max_transfer_bytes: u64,
    /// Comma-separated list of browser origins permitted to call the
    /// control plane. Empty = same-origin only (default). `*` for dev.
    pub cors_allowed_origins: Vec<String>,
    /// Shared-secret bearer token gating `/v1/admin/*` endpoints
    /// (API key management, usage queries, …). When `None`, admin
    /// endpoints return 503 with a clear message — we don't want
    /// silent 404s on a forgotten deploy secret.
    pub admin_token: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let database_url =
            env::var("DATABASE_URL").map_err(|_| ConfigError::Missing("DATABASE_URL"))?;

        let bind_addr_str = env::var("BIND_ADDR").unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string());
        let bind_addr: SocketAddr =
            bind_addr_str
                .parse()
                .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                    name: "BIND_ADDR",
                    msg: e.to_string(),
                })?;

        let audit_log_path = env::var("AUDIT_LOG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_AUDIT_LOG_PATH));

        let blob_dir = env::var("BLOB_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_BLOB_DIR));

        let signing_key_path = env::var("SIGNING_KEY_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(DEFAULT_SIGNING_KEY_PATH));

        let max_transfer_bytes = match env::var("MAX_TRANSFER_BYTES") {
            Ok(v) => v
                .parse()
                .map_err(|e: std::num::ParseIntError| ConfigError::Invalid {
                    name: "MAX_TRANSFER_BYTES",
                    msg: e.to_string(),
                })?,
            Err(_) => DEFAULT_MAX_TRANSFER_BYTES,
        };

        let cors_allowed_origins: Vec<String> = env::var("CORS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // Minimum entropy: reject obviously-short tokens so a fat
        // finger in a `fly secrets set` doesn't deploy a 4-byte
        // admin password. 32 chars matches the shape of a generated
        // `openssl rand -hex 16` secret.
        const MIN_ADMIN_TOKEN_LEN: usize = 32;
        let admin_token = match env::var("AEX_ADMIN_TOKEN") {
            Ok(v) if v.len() >= MIN_ADMIN_TOKEN_LEN => Some(v),
            Ok(v) if v.is_empty() => None,
            Ok(v) => {
                return Err(ConfigError::Invalid {
                    name: "AEX_ADMIN_TOKEN",
                    msg: format!(
                        "must be at least {} chars; got {} — generate with \
                         `openssl rand -hex 16`",
                        MIN_ADMIN_TOKEN_LEN,
                        v.len()
                    ),
                });
            }
            Err(_) => None,
        };

        Ok(Self {
            database_url,
            bind_addr,
            audit_log_path,
            blob_dir,
            signing_key_path,
            max_transfer_bytes,
            cors_allowed_origins,
            admin_token,
        })
    }
}
