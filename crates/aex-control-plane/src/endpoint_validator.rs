//! Parallel reachability probes for `reachable_at[]` endpoints.
//!
//! Per ADR-0014 a transfer may declare multiple endpoints; the control
//! plane must verify that at least one is actually reachable before it
//! hands the recipient a ticket. Per ADR-0033 all outbound validation
//! traffic is gated on a process-wide 50-permit semaphore so a burst of
//! concurrent `POST /v1/transfers` calls can't saturate the egress
//! socket pool. Per ADR-0021 the default probe budget is 15s total for
//! the whole `reachable_at[]` array — individual HTTP attempts get
//! shorter per-request timeouts so a single slow endpoint never burns
//! the whole budget.
//!
//! Design:
//!
//! - HTTP endpoints (`cloudflare_quick`, `cloudflare_named`,
//!   `tailscale_funnel`, `frp`) are probed with `GET <url>/healthz`.
//!   Success = HTTP 200-299.
//! - `iroh:*` URLs can't be probed without an Iroh client. They're
//!   marked "assumed healthy" for now; the real reachability check
//!   happens recipient-side when the SDK dials. Future work: add a
//!   cheap Iroh handshake probe.
//! - Unknown kinds stay in the array but are marked unhealthy so
//!   recipients skip them.
//!
//! The validator never mutates the endpoints. Callers inspect
//! [`ValidationReport::healthy_endpoints`] to project only the
//! reachable ones for downstream use.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aex_core::Endpoint;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Default global concurrent-probe cap (ADR-0033).
pub const DEFAULT_PERMITS: usize = 50;
/// Default budget for the full `reachable_at[]` probe batch (ADR-0014).
pub const DEFAULT_BUDGET: Duration = Duration::from_secs(15);
/// Per-request HTTP timeout. Shorter than the batch budget so a single
/// stuck endpoint never burns the whole thing.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, serde::Serialize)]
pub struct EndpointProbeResult {
    pub kind: String,
    pub url: String,
    pub priority: i32,
    pub healthy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

#[derive(Debug)]
pub struct ValidationReport {
    pub results: Vec<EndpointProbeResult>,
}

impl ValidationReport {
    pub fn at_least_one_healthy(&self) -> bool {
        self.results.iter().any(|r| r.healthy)
    }

    /// Subset of the input endpoints that passed the probe, preserving
    /// the original priority / insertion order.
    pub fn healthy_endpoints(&self, input: &[Endpoint]) -> Vec<Endpoint> {
        input
            .iter()
            .enumerate()
            .filter(|(i, _)| self.results.get(*i).map(|r| r.healthy).unwrap_or(false))
            .map(|(_, e)| e.clone())
            .collect()
    }
}

#[derive(Clone)]
pub struct EndpointValidator {
    semaphore: Arc<Semaphore>,
    budget: Duration,
    http: reqwest::Client,
}

impl EndpointValidator {
    pub fn new(permits: usize, budget: Duration) -> Result<Self, reqwest::Error> {
        Ok(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            budget,
            http: aex_net::build_http_client_with_timeout("control-plane", HTTP_REQUEST_TIMEOUT)
                .map_err(|e| {
                    // aex-net returns anyhow; we need a reqwest::Error at the
                    // type layer but can fall back to a bare builder here. If
                    // the aex-net build fails something is very wrong.
                    tracing::error!("aex_net http client build failed: {e}");
                    reqwest::Client::builder()
                        .timeout(HTTP_REQUEST_TIMEOUT)
                        .build()
                        .err()
                        .unwrap_or_else(|| panic!("could not build fallback http client: {e}"))
                })?,
        })
    }

    /// Default instance — DEFAULT_PERMITS + DEFAULT_BUDGET. Panics only
    /// if reqwest fails to build a client (effectively infallible on
    /// rustls).
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_PERMITS, DEFAULT_BUDGET)
            .expect("default EndpointValidator should always build")
    }

    /// Probe every endpoint in parallel, gated on the process semaphore.
    /// Returns one [`EndpointProbeResult`] per input endpoint in the
    /// same order.
    pub async fn validate_all(&self, endpoints: &[Endpoint]) -> ValidationReport {
        let deadline = Instant::now() + self.budget;
        let futs = endpoints.iter().map(|ep| {
            let sem = self.semaphore.clone();
            let http = self.http.clone();
            let ep = ep.clone();
            async move {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return EndpointProbeResult {
                        kind: ep.kind,
                        url: ep.url,
                        priority: ep.priority,
                        healthy: false,
                        error: Some("budget exhausted before probe started".into()),
                        latency_ms: None,
                    };
                }
                let _permit = sem.acquire().await.expect("semaphore is never closed");
                probe_endpoint(&http, &ep, remaining).await
            }
        });
        let results = futures::future::join_all(futs).await;
        ValidationReport { results }
    }
}

async fn probe_endpoint(
    http: &reqwest::Client,
    ep: &Endpoint,
    budget: Duration,
) -> EndpointProbeResult {
    match ep.kind.as_str() {
        Endpoint::KIND_CLOUDFLARE_QUICK
        | Endpoint::KIND_CLOUDFLARE_NAMED
        | Endpoint::KIND_TAILSCALE_FUNNEL
        | Endpoint::KIND_FRP => probe_http_healthz(http, ep, budget).await,
        Endpoint::KIND_IROH => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: true,
            error: None,
            latency_ms: None,
        },
        _ => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: false,
            error: Some(format!("unknown endpoint kind: {}", ep.kind)),
            latency_ms: None,
        },
    }
}

async fn probe_http_healthz(
    http: &reqwest::Client,
    ep: &Endpoint,
    budget: Duration,
) -> EndpointProbeResult {
    let healthz = format!("{}/healthz", ep.url.trim_end_matches('/'));
    let started = Instant::now();
    let req = http.get(&healthz).send();
    let res = timeout(budget, req).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match res {
        Ok(Ok(r)) if r.status().is_success() => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: true,
            error: None,
            latency_ms: Some(latency_ms),
        },
        Ok(Ok(r)) => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: false,
            error: Some(format!("http status {}", r.status())),
            latency_ms: Some(latency_ms),
        },
        Ok(Err(e)) => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: false,
            error: Some(e.to_string()),
            latency_ms: Some(latency_ms),
        },
        Err(_) => EndpointProbeResult {
            kind: ep.kind.clone(),
            url: ep.url.clone(),
            priority: ep.priority,
            healthy: false,
            error: Some(format!("timeout after {}ms", latency_ms)),
            latency_ms: Some(latency_ms),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(kind: &str, url: &str, priority: i32) -> Endpoint {
        Endpoint {
            kind: kind.into(),
            url: url.into(),
            priority,
            health_hint_unix: None,
            health: None,
        }
    }

    #[tokio::test]
    async fn iroh_endpoints_assumed_healthy_without_probing() {
        let v = EndpointValidator::with_defaults();
        let eps = vec![ep(Endpoint::KIND_IROH, "iroh:deadbeef@relay.ams", 0)];
        let report = v.validate_all(&eps).await;
        assert!(report.at_least_one_healthy());
        assert_eq!(report.results.len(), 1);
        assert!(report.results[0].healthy);
    }

    #[tokio::test]
    async fn unknown_kind_marked_unhealthy() {
        let v = EndpointValidator::with_defaults();
        let eps = vec![ep("future_transport_v9", "future:alien@mars:443", 5)];
        let report = v.validate_all(&eps).await;
        assert!(!report.at_least_one_healthy());
        assert_eq!(report.results.len(), 1);
        assert!(!report.results[0].healthy);
        assert!(report.results[0]
            .error
            .as_deref()
            .unwrap_or("")
            .contains("unknown endpoint kind"));
    }

    #[tokio::test]
    async fn healthy_endpoints_preserves_order() {
        let v = EndpointValidator::with_defaults();
        // Two iroh endpoints (both "healthy") + one unknown (not healthy).
        let eps = vec![
            ep(Endpoint::KIND_IROH, "iroh:a", 2),
            ep("garbage", "bad://", 1),
            ep(Endpoint::KIND_IROH, "iroh:b", 0),
        ];
        let report = v.validate_all(&eps).await;
        let healthy = report.healthy_endpoints(&eps);
        assert_eq!(healthy.len(), 2);
        assert_eq!(healthy[0].url, "iroh:a");
        assert_eq!(healthy[1].url, "iroh:b");
    }

    #[tokio::test]
    async fn unreachable_http_endpoint_times_out_within_budget() {
        // RFC 5737 TEST-NET-1 address — guaranteed not routable.
        // Use a tight budget so the test runs quickly.
        let v = EndpointValidator::new(50, Duration::from_secs(2)).unwrap();
        let eps = vec![ep(Endpoint::KIND_CLOUDFLARE_QUICK, "https://192.0.2.1", 0)];
        let report = v.validate_all(&eps).await;
        assert!(!report.at_least_one_healthy());
        assert!(report.results[0].error.is_some());
    }
}
