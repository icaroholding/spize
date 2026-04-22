//! Prometheus metrics for the control plane (Sprint 3).
//!
//! A single [`Metrics`] struct owns every counter, gauge, and histogram
//! the CP exposes. It holds its own [`prometheus::Registry`] rather
//! than registering into the global default registry — that keeps the
//! test surface clean (each `#[sqlx::test]` gets a fresh counter set
//! via a fresh `AppState`, so assertions aren't polluted by other
//! tests running in the same process).
//!
//! The struct is cheap to `Clone` (all fields are `Arc`-backed via
//! `prometheus`'s internal `Mutex`es) so handlers can increment via
//! `state.metrics.transfers_created.inc()` without a lock dance.

use std::sync::Arc;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

/// Every metric series the control plane exports. Clone is cheap;
/// hand the struct to every handler that needs to emit metrics.
#[derive(Clone)]
pub struct Metrics {
    /// Private registry so tests can inspect / reset without touching
    /// the process-wide default.
    registry: Arc<Registry>,

    // ---- agent lifecycle ----
    pub agents_registered_total: IntCounter,
    pub agents_key_rotated_total: IntCounter,

    // ---- transfer lifecycle ----
    /// Labelled by `recipient_kind` = spize_native | did | human_bridge | unknown.
    pub transfers_created_total: IntCounterVec,
    pub transfers_delivered_total: IntCounter,
    /// Labelled by `reason` = scanner | policy | nonce_replay | endpoint_unreachable.
    pub transfers_rejected_total: IntCounterVec,

    // ---- endpoint health monitor ----
    /// Labelled by `outcome` = success | failure.
    pub health_probes_total: IntCounterVec,
    /// Labelled by `direction` = to_healthy | to_unhealthy.
    pub health_transitions_total: IntCounterVec,
    /// Gauge of currently-known in-flight transfers. Set by the
    /// health monitor each tick.
    pub in_flight_transfers: IntGauge,

    // ---- endpoint probe latency ----
    /// Labelled by `kind` (cloudflare_quick / iroh / …). Buckets
    /// tuned for a `/healthz` roundtrip: expect single-digit ms in
    /// LAN-close tests, seconds on slow wifi.
    pub endpoint_probe_duration_seconds: HistogramVec,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Arc::new(Registry::new());

        let agents_registered_total = IntCounter::with_opts(Opts::new(
            "aex_agents_registered_total",
            "Number of POST /v1/agents/register calls that produced a new agent row.",
        ))
        .expect("agents_registered_total opts valid");
        registry
            .register(Box::new(agents_registered_total.clone()))
            .expect("register agents_registered_total");

        let agents_key_rotated_total = IntCounter::with_opts(Opts::new(
            "aex_agents_key_rotated_total",
            "Successful POST /v1/agents/rotate-key calls (ADR-0024).",
        ))
        .expect("agents_key_rotated_total opts valid");
        registry
            .register(Box::new(agents_key_rotated_total.clone()))
            .expect("register agents_key_rotated_total");

        let transfers_created_total = IntCounterVec::new(
            Opts::new(
                "aex_transfers_created_total",
                "Successful POST /v1/transfers calls. Labelled by recipient_kind.",
            ),
            &["recipient_kind"],
        )
        .expect("transfers_created_total opts valid");
        registry
            .register(Box::new(transfers_created_total.clone()))
            .expect("register transfers_created_total");

        let transfers_delivered_total = IntCounter::with_opts(Opts::new(
            "aex_transfers_delivered_total",
            "Transfers moved to the `delivered` state by a recipient ack.",
        ))
        .expect("transfers_delivered_total opts valid");
        registry
            .register(Box::new(transfers_delivered_total.clone()))
            .expect("register transfers_delivered_total");

        let transfers_rejected_total = IntCounterVec::new(
            Opts::new(
                "aex_transfers_rejected_total",
                "Rejected transfers, labelled by reason (scanner, policy, nonce_replay, endpoint_unreachable).",
            ),
            &["reason"],
        )
        .expect("transfers_rejected_total opts valid");
        registry
            .register(Box::new(transfers_rejected_total.clone()))
            .expect("register transfers_rejected_total");

        let health_probes_total = IntCounterVec::new(
            Opts::new(
                "aex_health_probes_total",
                "Endpoint probes performed by the background health monitor, labelled by outcome.",
            ),
            &["outcome"],
        )
        .expect("health_probes_total opts valid");
        registry
            .register(Box::new(health_probes_total.clone()))
            .expect("register health_probes_total");

        let health_transitions_total = IntCounterVec::new(
            Opts::new(
                "aex_health_transitions_total",
                "Endpoint health transitions (to_healthy / to_unhealthy) — counts the asymmetric debouncer flipping (ADR-0021).",
            ),
            &["direction"],
        )
        .expect("health_transitions_total opts valid");
        registry
            .register(Box::new(health_transitions_total.clone()))
            .expect("register health_transitions_total");

        let in_flight_transfers = IntGauge::with_opts(Opts::new(
            "aex_in_flight_transfers",
            "Transfers currently in state `ready_for_pickup`. Refreshed each health-monitor tick.",
        ))
        .expect("in_flight_transfers opts valid");
        registry
            .register(Box::new(in_flight_transfers.clone()))
            .expect("register in_flight_transfers");

        let endpoint_probe_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "aex_endpoint_probe_duration_seconds",
                "Latency of an endpoint reachability probe, labelled by transport kind.",
            )
            .buckets(vec![0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
            &["kind"],
        )
        .expect("endpoint_probe_duration_seconds opts valid");
        registry
            .register(Box::new(endpoint_probe_duration_seconds.clone()))
            .expect("register endpoint_probe_duration_seconds");

        Self {
            registry,
            agents_registered_total,
            agents_key_rotated_total,
            transfers_created_total,
            transfers_delivered_total,
            transfers_rejected_total,
            health_probes_total,
            health_transitions_total,
            in_flight_transfers,
            endpoint_probe_duration_seconds,
        }
    }

    /// Render the metric set in Prometheus text exposition format.
    /// Used by the `GET /metrics` handler.
    pub fn render(&self) -> String {
        let mut buf = Vec::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        // TextEncoder on a well-formed registry cannot fail; defensive
        // fallback keeps the endpoint from panicking if that ever
        // changes upstream.
        if encoder.encode(&families, &mut buf).is_err() {
            return String::from("# metrics encoding failed\n");
        }
        String::from_utf8(buf).unwrap_or_else(|_| String::from("# metrics encoding non-utf8\n"))
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_registry_emits_scalar_families() {
        // prometheus-rs only emits HELP/TYPE for scalar counters and
        // gauges by default — *Vec families without any observed
        // label combinations stay silent. We still assert the scalar
        // ones so a botched registration (typo / wrong metric type)
        // surfaces in unit tests.
        let m = Metrics::new();
        let out = m.render();
        assert!(out.contains("aex_agents_registered_total"));
        assert!(out.contains("aex_agents_key_rotated_total"));
        assert!(out.contains("aex_transfers_delivered_total"));
        assert!(out.contains("aex_in_flight_transfers"));
    }

    #[test]
    fn increments_survive_round_trip() {
        let m = Metrics::new();
        m.agents_registered_total.inc();
        m.agents_registered_total.inc();
        m.transfers_created_total
            .with_label_values(&["spize_native"])
            .inc();
        m.transfers_rejected_total
            .with_label_values(&["scanner"])
            .inc();

        let out = m.render();
        assert!(out.contains("aex_agents_registered_total 2"));
        assert!(out.contains(r#"aex_transfers_created_total{recipient_kind="spize_native"} 1"#));
        assert!(out.contains(r#"aex_transfers_rejected_total{reason="scanner"} 1"#));
    }

    #[test]
    fn histogram_observe_exposes_bucket_counts() {
        let m = Metrics::new();
        m.endpoint_probe_duration_seconds
            .with_label_values(&["cloudflare_quick"])
            .observe(0.123);
        let out = m.render();
        // Bucket counters and _sum / _count are all present.
        assert!(out.contains("aex_endpoint_probe_duration_seconds_bucket"));
        assert!(out.contains("aex_endpoint_probe_duration_seconds_sum"));
        assert!(out.contains("aex_endpoint_probe_duration_seconds_count"));
    }

    #[test]
    fn gauge_roundtrips() {
        let m = Metrics::new();
        m.in_flight_transfers.set(42);
        let out = m.render();
        assert!(out.contains("aex_in_flight_transfers 42"));
    }

    #[test]
    fn output_is_prometheus_text_format_compatible() {
        // A simple sanity: every non-blank, non-comment line must
        // match `NAME{...}? VALUE` after splitting on whitespace.
        let m = Metrics::new();
        m.agents_registered_total.inc();
        m.transfers_created_total
            .with_label_values(&["spize_native"])
            .inc();
        let out = m.render();
        for line in out.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.rsplitn(2, char::is_whitespace).collect();
            assert_eq!(
                parts.len(),
                2,
                "malformed line in exposition output: {line:?}"
            );
            // The value is parseable as a float.
            assert!(
                parts[0].parse::<f64>().is_ok(),
                "last token on {line:?} must be a float"
            );
        }
    }
}
