//! Tailscale Funnel tunnel provider.
//!
//! Exposes a local port to the public internet via the operator's
//! Tailscale node's Funnel hostname (`<node>.<tailnet>.ts.net`). The
//! operator has already:
//! - authenticated the node (`tailscale up`)
//! - turned funnel on in the tailnet ACL
//! and supplies the externally-visible URL at construction time. This
//! provider orchestrates `tailscale funnel --bg <port>` to wire the
//! local port to the funnel hostname and `tailscale funnel off` on
//! stop to clean up.
//!
//! Tailscale's own `tailscaled` daemon owns the long-lived connection;
//! the commands we run are short-lived state mutators. That's why we
//! don't keep a `Child` handle around — the lifecycle of the funnel
//! state is independent from our process.

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

use crate::{
    provider::{TunnelProvider, TunnelStatus},
    TunnelError, TunnelResult,
};

const DEFAULT_READY_TIMEOUT: Duration = Duration::from_secs(30);
const PROBE_INTERVAL: Duration = Duration::from_secs(2);
const PROBE_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

const CANDIDATE_PATHS: &[&str] = &[
    "tailscale",
    "/opt/homebrew/bin/tailscale",
    "/usr/local/bin/tailscale",
    "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
];

pub struct TailscaleFunnelTunnel {
    public_url: String,
    binary_path: Option<String>,
    ready_timeout: Duration,
    status: TunnelStatus,
    active: bool,
    cached_url: Option<String>,
}

impl TailscaleFunnelTunnel {
    pub fn new(public_url: impl Into<String>) -> Self {
        Self {
            public_url: public_url.into(),
            binary_path: None,
            ready_timeout: DEFAULT_READY_TIMEOUT,
            status: TunnelStatus::Disconnected {
                reason: "not started".into(),
            },
            active: false,
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

    fn resolve_binary(&self) -> TunnelResult<String> {
        if let Some(p) = &self.binary_path {
            return Ok(p.clone());
        }
        for path in CANDIDATE_PATHS {
            let exists = std::process::Command::new(path)
                .arg("version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok();
            if exists {
                return Ok((*path).to_string());
            }
        }
        Err(TunnelError::Other(format!(
            "tailscale binary not found; tried {:?}",
            CANDIDATE_PATHS
        )))
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
impl TunnelProvider for TailscaleFunnelTunnel {
    async fn start(&mut self, local_port: u16) -> TunnelResult<()> {
        if self.active {
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

        // `tailscale funnel --bg <port>` installs a background funnel
        // rule so tailscaled keeps serving it; the command exits once
        // the rule is in place.
        let output = Command::new(&binary)
            .args(["funnel", "--bg", &local_port.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                self.status = TunnelStatus::Disconnected {
                    reason: format!("spawn: {e}"),
                };
                TunnelError::Spawn(e)
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            self.status = TunnelStatus::Disconnected {
                reason: stderr.clone(),
            };
            return Err(TunnelError::Other(format!(
                "tailscale funnel exited {}: {stderr}",
                output.status
            )));
        }
        self.active = true;

        if let Err(e) = self.probe_until_ready().await {
            let _ = self.stop().await;
            return Err(e);
        }

        self.cached_url = Some(self.public_url.clone());
        self.status = TunnelStatus::Connected {
            url: self.public_url.clone(),
        };
        Ok(())
    }

    async fn stop(&mut self) -> TunnelResult<()> {
        if !self.active {
            self.status = TunnelStatus::Disconnected {
                reason: "stopped".into(),
            };
            self.cached_url = None;
            return Ok(());
        }
        let binary = self.resolve_binary()?;
        let _ = Command::new(&binary)
            .args(["funnel", "off"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;
        self.active = false;
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

    #[test]
    fn builder_overrides_applied() {
        let t = TailscaleFunnelTunnel::new("https://alice.tail1234.ts.net")
            .with_binary_path("/opt/tailscale")
            .with_ready_timeout(Duration::from_secs(2));
        assert_eq!(t.ready_timeout, Duration::from_secs(2));
        assert_eq!(t.binary_path.as_deref(), Some("/opt/tailscale"));
        assert_eq!(t.public_url, "https://alice.tail1234.ts.net");
    }

    #[test]
    fn resolve_binary_honors_override() {
        let t = TailscaleFunnelTunnel::new("https://x.ts.net")
            .with_binary_path("/nonexistent/tailscale");
        assert_eq!(t.resolve_binary().unwrap(), "/nonexistent/tailscale");
    }

    #[tokio::test]
    async fn stop_without_start_is_noop() {
        let mut t = TailscaleFunnelTunnel::new("https://x.ts.net");
        t.stop().await.unwrap();
        assert!(t.public_url().is_none());
        assert!(matches!(t.status(), TunnelStatus::Disconnected { .. }));
    }
}
