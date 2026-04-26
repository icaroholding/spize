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
    /// Stripe webhook config. When any field is `None` the webhook
    /// endpoint returns 503 with a pointer at the runbook — same
    /// philosophy as `admin_token`: fail loud on misconfiguration.
    pub stripe: StripeConfig,
    /// Customer dashboard / magic-link config (Sprint 4 PR 7).
    /// When any field is `None` the customer-auth endpoints return
    /// 503 — fail loud on misconfiguration.
    pub customer_auth: CustomerAuthConfig,
    /// Resend transactional email config. Required for the magic-
    /// link delivery; if `None` the magic-link endpoint will return
    /// the token in the response body for development workflows.
    pub email: EmailConfig,
}

/// Settings for the customer dashboard surface — JWT signing
/// secret + frontend base URL the magic-link in email points at.
#[derive(Debug, Clone, Default)]
pub struct CustomerAuthConfig {
    /// HS256 signing secret for session JWTs. Generated via
    /// `openssl rand -hex 32`. When `None`, every customer-auth
    /// endpoint returns 503.
    pub session_secret: Option<String>,
    /// Frontend origin the magic-link URL points at. The link the
    /// customer clicks is built as `{frontend_base_url}/auth/callback?token=…`,
    /// so the frontend's auth-callback page reads `token` from the
    /// query string and POSTs it to `/v1/customer/auth/magic-link/verify`.
    /// In dev: `http://localhost:3000`. In prod: `https://spize.io`.
    pub frontend_base_url: Option<String>,
}

impl CustomerAuthConfig {
    pub fn is_ready(&self) -> bool {
        self.session_secret.is_some() && self.frontend_base_url.is_some()
    }
}

/// Resend transactional-email integration. Optional: when missing,
/// magic-link request returns the token to the caller as a dev-mode
/// convenience instead of mailing it.
#[derive(Debug, Clone, Default)]
pub struct EmailConfig {
    /// Resend API key (`re_…`). Used as `Authorization: Bearer …`
    /// against `https://api.resend.com/emails`.
    pub resend_api_key: Option<String>,
    /// `From` header on every transactional email. Defaults to
    /// `Spize <noreply@spize.io>`. Override via `MAIL_FROM` only if
    /// the verified domain on Resend changes.
    pub mail_from: String,
}

/// Stripe integration settings. Grouped so it's obvious at call
/// sites ("the Stripe surface") and so tests can build a coherent
/// fake without touching unrelated env vars.
#[derive(Debug, Clone, Default)]
pub struct StripeConfig {
    /// Shared webhook signing secret from the Stripe dashboard
    /// (`whsec_…`). Required to verify that an incoming POST is
    /// really from Stripe. When `None`, the webhook handler returns
    /// 503.
    pub webhook_secret: Option<String>,
    /// Stripe `price.id` that maps to the `dev` tier (e.g.
    /// `$29/month` at Sprint 4 launch). When a
    /// `customer.subscription.*` event references this price, the
    /// resulting `subscriptions` row is tagged `tier = "dev"` and
    /// the customer dashboard will hand out `dev`-tier API keys.
    pub price_dev: Option<String>,
    /// Same as above for the `team` tier (e.g. `$99/month`).
    pub price_team: Option<String>,
}

impl StripeConfig {
    /// True iff the webhook is fully configured. Handlers short-
    /// circuit with a 503 when this is false, which happens in dev
    /// or on a forgotten-secret deploy.
    pub fn is_ready(&self) -> bool {
        self.webhook_secret.is_some() && self.price_dev.is_some() && self.price_team.is_some()
    }
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

        let stripe = StripeConfig {
            webhook_secret: env::var("STRIPE_WEBHOOK_SECRET")
                .ok()
                .filter(|v| !v.is_empty()),
            price_dev: env::var("STRIPE_PRICE_DEV").ok().filter(|v| !v.is_empty()),
            price_team: env::var("STRIPE_PRICE_TEAM").ok().filter(|v| !v.is_empty()),
        };
        if !stripe.is_ready() {
            tracing::warn!(
                webhook_secret = stripe.webhook_secret.is_some(),
                price_dev = stripe.price_dev.is_some(),
                price_team = stripe.price_team.is_some(),
                "Stripe webhook not fully configured; /webhooks/stripe will return 503. \
                 Set STRIPE_WEBHOOK_SECRET + STRIPE_PRICE_DEV + STRIPE_PRICE_TEAM."
            );
        }

        const MIN_SESSION_SECRET_LEN: usize = 32;
        let session_secret = match env::var("AEX_SESSION_SECRET") {
            Ok(v) if v.len() >= MIN_SESSION_SECRET_LEN => Some(v),
            Ok(v) if v.is_empty() => None,
            Ok(v) => {
                return Err(ConfigError::Invalid {
                    name: "AEX_SESSION_SECRET",
                    msg: format!(
                        "must be at least {} chars; got {} — generate with \
                         `openssl rand -hex 32`",
                        MIN_SESSION_SECRET_LEN,
                        v.len()
                    ),
                });
            }
            Err(_) => None,
        };
        let customer_auth = CustomerAuthConfig {
            session_secret,
            frontend_base_url: env::var("AEX_FRONTEND_BASE_URL")
                .ok()
                .filter(|v| !v.is_empty()),
        };
        if !customer_auth.is_ready() {
            tracing::warn!(
                session_secret = customer_auth.session_secret.is_some(),
                frontend_base_url = customer_auth.frontend_base_url.is_some(),
                "Customer auth not fully configured; /v1/customer/* will return 503. \
                 Set AEX_SESSION_SECRET + AEX_FRONTEND_BASE_URL."
            );
        }

        let email = EmailConfig {
            resend_api_key: env::var("RESEND_API_KEY").ok().filter(|v| !v.is_empty()),
            mail_from: env::var("MAIL_FROM")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "Spize <noreply@spize.io>".to_string()),
        };
        if email.resend_api_key.is_none() {
            tracing::warn!(
                "RESEND_API_KEY not set; magic-link email delivery falls back to \
                 returning the token in the response body for dev workflows."
            );
        }

        Ok(Self {
            database_url,
            bind_addr,
            audit_log_path,
            blob_dir,
            signing_key_path,
            max_transfer_bytes,
            cors_allowed_origins,
            admin_token,
            stripe,
            customer_auth,
            email,
        })
    }
}
