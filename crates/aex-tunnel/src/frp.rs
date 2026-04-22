//! FRP (Fast Reverse Proxy) tunnel provider.
//!
//! `frpc` is the client half of a self-hosted FRP deployment: the
//! operator runs a public `frps` server on a rented VPS and `frpc`
//! connects out from behind NAT to register an HTTP subdomain whose
//! traffic is reverse-proxied to a local port. The public URL is a
//! pre-negotiated subdomain on the operator's domain — we never
//! discover it at runtime.
//!
//! This provider:
//! - writes a minimal `frpc.toml` to a tempfile at `start()` time so we
//!   don't have to ship the operator a sample config;
//! - spawns `frpc -c <path>`;
//! - probes the configured public URL until it answers `/healthz` with
//!   a 2xx;
//! - kills the child on `stop()`.
//!
//! Kill-on-drop is enabled so a panicked caller doesn't leak the
//! `frpc` process.

use std::io::Write;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout};

use crate::{
    provider::{TunnelProvider, TunnelStatus},
    TunnelError, TunnelResult,
};

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(60);
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

const CANDIDATE_PATHS: &[&str] = &["frpc", "/opt/homebrew/bin/frpc", "/usr/local/bin/frpc"];

/// Connection settings for a pre-configured `frps` server.
#[derive(Debug, Clone)]
pub struct FrpServer {
    pub addr: String,
    pub port: u16,
    pub token: String,
    /// Subdomain registered on the server (e.g. `alice` → `alice.frp.example.com`).
    pub subdomain: String,
}

pub struct FrpTunnel {
    server: FrpServer,
    public_url: String,
    binary_path: Option<String>,
    ready_timeout: Duration,
    child: Option<Child>,
    config_file: Option<tempfile::NamedTempFile>,
    status: TunnelStatus,
    cached_url: Option<String>,
}

impl FrpTunnel {
    pub fn new(server: FrpServer, public_url: impl Into<String>) -> Self {
        Self {
            server,
            public_url: public_url.into(),
            binary_path: None,
            ready_timeout: DEFAULT_READY_TIMEOUT,
            child: None,
            config_file: None,
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            cached_url: None,
        }
    }

    pub fn with_binary_path(mut self, path: impl Into<String>) -> Self {
        self.binary_path = Some(path.into());
        self
    }

    pub fn with_ready_timeout(mut self, timeout: Duration) -> Self {
        self.ready_timeout = timeout;
        self
    }

    pub fn is_alive(&mut self) -> bool {
        let Some(child) = self.child.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(Some(_)) => {
                self.status = TunnelStatus::Disconnected {
                    reason: "process exited".into(),
                };
                self.cached_url = None;
                false
            }
            Ok(None) => true,
            Err(_) => false,
        }
    }

    fn resolve_binary(&self) -> TunnelResult<String> {
        if let Some(p) = &self.binary_path {
            return Ok(p.clone());
        }
        for path in CANDIDATE_PATHS {
            let exists = std::process::Command::new(path)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok();
            if exists {
                return Ok((*path).to_string());
            }
        }
        Err(TunnelError::Other(format!(
            "frpc binary not found; tried {:?}",
            CANDIDATE_PATHS
        )))
    }

    fn render_config(&self, local_port: u16) -> String {
        format!(
            concat!(
                "serverAddr = \"{addr}\"\n",
                "serverPort = {port}\n",
                "auth.token = \"{token}\"\n",
                "\n",
                "[[proxies]]\n",
                "name = \"aex-{subdomain}\"\n",
                "type = \"http\"\n",
                "localIP = \"127.0.0.1\"\n",
                "localPort = {local_port}\n",
                "subdomain = \"{subdomain}\"\n",
            ),
            addr = self.server.addr,
            port = self.server.port,
            token = self.server.token,
            subdomain = self.server.subdomain,
            local_port = local_port,
        )
    }

    async fn probe_until_ready(&self) -> TunnelResult<()> {
        let healthz = format!("{}/healthz", self.public_url.trim_end_matches('/'));
        let client = reqwest::Client::builder()
            .timeout(PROBE_HTTP_TIMEOUT)
            .build()
            .map_err(|e| TunnelError::Other(format!("reqwest build: {e}")))?;
        let poll = async {
            loop {
                if let Ok(r) = client.get(&healthz).send().await {
                    if r.status().is_success() {
                        return Ok(());
                    }
                }
                sleep(PROBE_INTERVAL).await;
            }
        };
        timeout(self.ready_timeout, poll)
            .await
            .map_err(|_| TunnelError::UrlTimeout {
                secs: self.ready_timeout.as_secs(),
            })?
    }
}

#[async_trait]
impl TunnelProvider for FrpTunnel {
    async fn start(&mut self, local_port: u16) -> TunnelResult<()> {
        if self.child.is_some() {
            return Err(TunnelError::AlreadyRunning);
        }
        self.status = TunnelStatus::Connecting;
        let binary = match self.resolve_binary() {
            Ok(b) => b,
            Err(e) => {
                self.status = TunnelStatus::Disconnected {
                    reason: e.to_string(),
                };
                return Err(e);
            }
        };

        // Write a tempfile config with an explicit `.toml` suffix so
        // frpc auto-detects the TOML parser rather than falling back
        // to the legacy INI reader.
        let mut cfg = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .map_err(|e| {
                self.status = TunnelStatus::Disconnected {
                    reason: format!("tempfile: {e}"),
                };
                TunnelError::Spawn(e)
            })?;
        cfg.as_file_mut()
            .write_all(self.render_config(local_port).as_bytes())
            .map_err(|e| {
                self.status = TunnelStatus::Disconnected {
                    reason: format!("config write: {e}"),
                };
                TunnelError::Spawn(e)
            })?;

        let child = Command::new(&binary)
            .args(["-c", cfg.path().to_str().unwrap()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| {
                self.status = TunnelStatus::Disconnected {
                    reason: format!("spawn: {e}"),
                };
                TunnelError::Spawn(e)
            })?;
        self.child = Some(child);
        self.config_file = Some(cfg);

        if let Err(e) = self.probe_until_ready().await {
            self.status = TunnelStatus::Disconnected {
                reason: e.to_string(),
            };
            if let Some(mut c) = self.child.take() {
                let _ = c.kill().await;
            }
            self.config_file = None;
            return Err(e);
        }

        self.cached_url = Some(self.public_url.clone());
        self.status = TunnelStatus::Connected {
            url: self.public_url.clone(),
        };
        Ok(())
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill().await;
        }
        self.config_file = None;
        self.cached_url = None;
        self.status = TunnelStatus::Disconnected {
            reason: "stopped".into(),
        };
        Ok(())
    }

    fn public_url(&self) -> Option<String> {
        self.cached_url.clone()
    }

    fn status(&self) -> TunnelStatus {
        self.status.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> FrpServer {
        FrpServer {
            addr: "frp.example.com".into(),
            port: 7000,
            token: "secret".into(),
            subdomain: "alice".into(),
        }
    }

    #[test]
    fn builder_overrides_applied() {
        let t = FrpTunnel::new(server(), "https://alice.frp.example.com")
            .with_binary_path("/opt/frpc")
            .with_ready_timeout(Duration::from_secs(3));
        assert_eq!(t.ready_timeout, Duration::from_secs(3));
        assert_eq!(t.binary_path.as_deref(), Some("/opt/frpc"));
        assert_eq!(t.public_url, "https://alice.frp.example.com");
    }

    #[test]
    fn resolve_binary_honors_override() {
        let t = FrpTunnel::new(server(), "https://alice.frp.example.com")
            .with_binary_path("/nonexistent/frpc");
        assert_eq!(t.resolve_binary().unwrap(), "/nonexistent/frpc");
    }

    #[test]
    fn render_config_contains_all_fields() {
        let t = FrpTunnel::new(server(), "https://alice.frp.example.com");
        let cfg = t.render_config(8080);
        assert!(cfg.contains("serverAddr = \"frp.example.com\""));
        assert!(cfg.contains("serverPort = 7000"));
        assert!(cfg.contains("auth.token = \"secret\""));
        assert!(cfg.contains("subdomain = \"alice\""));
        assert!(cfg.contains("localPort = 8080"));
        assert!(cfg.contains("type = \"http\""));
    }

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let mut t = FrpTunnel::new(server(), "https://alice.frp.example.com");
        t.stop().await.unwrap();
        assert!(t.public_url().is_none());
        assert!(matches!(t.status(), TunnelStatus::Disconnected { .. }));
    }
}
