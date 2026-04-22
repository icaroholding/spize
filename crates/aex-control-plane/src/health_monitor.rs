//! Background endpoint health loop (ADR-0014 + ADR-0021).
//!
//! The control plane admits a transfer only after at least one
//! `reachable_at[]` endpoint passes `/healthz`, but that single probe
//! happens at `create_transfer` time and can't catch a tunnel that dies
//! five minutes later. This module runs a Tokio task that re-probes
//! every endpoint on every `ready_for_pickup` transfer on a cadence
//! and folds each result through the asymmetric debouncer in
//! [`aex_core::EndpointHealth`] — 3 consecutive failures flip an
//! endpoint to `Unhealthy`, 2 consecutive successes flip it back. The
//! updated health state lands back in `transfers.reachable_at` JSONB
//! so observability and any future multi-URL ticket logic share a
//! single source of truth (ADR-0021's "persisted in reachable_at[]").
//!
//! The module is split into three pieces to keep the test surface
//! manageable:
//!
//! - [`EndpointProber`] — a trait that abstracts "is this endpoint up
//!   right now?" so tests can script outcomes without binding to
//!   [`crate::endpoint_validator::EndpointValidator`] or to real HTTP.
//! - [`HealthMonitor::tick`] — one pass over all in-flight transfers.
//!   Public so integration tests can drive the loop step-by-step with
//!   a mock prober.
//! - [`HealthMonitor::run`] — the production loop: `tick` every 30 s
//!   when at least one transfer is in-flight, 5 min otherwise,
//!   honouring an injected [`crate::clock::Clock`] for timestamps and
//!   a `tokio::sync::watch` shutdown signal for graceful termination.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use sqlx::PgPool;
use tokio::sync::watch;

use aex_core::{Endpoint, EndpointHealth, HealthStatus};

use crate::clock::Clock;
use crate::endpoint_validator::EndpointValidator;
use crate::metrics::Metrics;

/// Cadence while at least one transfer is in-flight. 30 s lines up
/// with the wall-clock budget callers see on `send_via_tunnel` and is
/// short enough for a flap to clear inside the typical recipient
/// retry window.
pub const IN_FLIGHT_INTERVAL: Duration = Duration::from_secs(30);
/// Cadence when there is nothing to probe. Prevents the DB from being
/// hammered at idle while still keeping health timestamps roughly
/// fresh.
pub const AT_REST_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Outcome of a single endpoint probe. The state machine doesn't need
/// to know *why* the probe failed — just whether it succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    Success,
    Failure,
}

/// Source of probe outcomes for the health monitor. Production code
/// wraps [`EndpointValidator`]; tests use a scripted mock.
#[async_trait]
pub trait EndpointProber: Send + Sync {
    async fn probe(&self, endpoint: &Endpoint) -> ProbeOutcome;
}

/// Production prober: delegates to [`EndpointValidator`] and collapses
/// its richer `ValidationReport` into a single [`ProbeOutcome`].
pub struct ValidatorProber {
    validator: EndpointValidator,
}

impl ValidatorProber {
    pub fn new(validator: EndpointValidator) -> Self {
        Self { validator }
    }
}

#[async_trait]
impl EndpointProber for ValidatorProber {
    async fn probe(&self, endpoint: &Endpoint) -> ProbeOutcome {
        let report = self
            .validator
            .validate_all(std::slice::from_ref(endpoint))
            .await;
        if report.at_least_one_healthy() {
            ProbeOutcome::Success
        } else {
            ProbeOutcome::Failure
        }
    }
}

/// Periodic re-validator. Owns the DB pool, the prober, the clock, the
/// metrics registry, and a shutdown signal.
pub struct HealthMonitor {
    db: PgPool,
    prober: Arc<dyn EndpointProber>,
    clock: Arc<dyn Clock>,
    metrics: Option<Metrics>,
    shutdown: watch::Receiver<bool>,
}

/// Handle returned by [`HealthMonitor::spawn`]. Dropping the handle
/// does NOT stop the monitor; callers must call `shutdown()` and then
/// `await` the join handle to terminate gracefully.
pub struct HealthMonitorHandle {
    shutdown_tx: watch::Sender<bool>,
    join: tokio::task::JoinHandle<()>,
}

impl HealthMonitorHandle {
    /// Signal the monitor to stop after its next tick. Returns the
    /// join handle so callers can await completion.
    pub async fn shutdown(self) -> Result<(), tokio::task::JoinError> {
        // Ignore send errors: if the receiver is already dropped the
        // task has already exited.
        let _ = self.shutdown_tx.send(true);
        self.join.await
    }
}

impl HealthMonitor {
    pub fn new(
        db: PgPool,
        prober: Arc<dyn EndpointProber>,
        clock: Arc<dyn Clock>,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            db,
            prober,
            clock,
            metrics: None,
            shutdown,
        }
    }

    /// Attach a [`Metrics`] registry. The monitor then emits counters
    /// for probe outcomes + state transitions and a gauge for
    /// in-flight transfer count each tick. Optional so unit tests can
    /// skip the metrics wiring entirely.
    pub fn with_metrics(mut self, metrics: Metrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Spawn the monitor on the current tokio runtime. Production
    /// wiring uses [`ValidatorProber`] and [`crate::clock::SystemClock`].
    pub fn spawn(
        db: PgPool,
        prober: Arc<dyn EndpointProber>,
        clock: Arc<dyn Clock>,
        metrics: Metrics,
    ) -> HealthMonitorHandle {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let monitor = HealthMonitor::new(db, prober, clock, shutdown_rx).with_metrics(metrics);
        let join = tokio::spawn(async move {
            monitor.run().await;
        });
        HealthMonitorHandle { shutdown_tx, join }
    }

    /// Production loop: tick, sleep for the adaptive interval, repeat
    /// until shutdown.
    async fn run(mut self) {
        tracing::info!(
            in_flight_interval_s = IN_FLIGHT_INTERVAL.as_secs(),
            at_rest_interval_s = AT_REST_INTERVAL.as_secs(),
            "health monitor started"
        );
        loop {
            let tick_result = self.tick().await;
            let interval = match tick_result {
                Ok(touched) if touched > 0 => IN_FLIGHT_INTERVAL,
                Ok(_) => AT_REST_INTERVAL,
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "health monitor tick failed; backing off at_rest interval"
                    );
                    AT_REST_INTERVAL
                }
            };
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = self.shutdown.changed() => {
                    if *self.shutdown.borrow() {
                        tracing::info!("health monitor shutting down");
                        return;
                    }
                }
            }
        }
    }

    /// Run one full probe pass. Returns the number of transfers
    /// touched, so callers can distinguish in-flight from at-rest
    /// state for cadence selection. Public for integration tests.
    pub async fn tick(&self) -> Result<usize, sqlx::Error> {
        let rows = load_in_flight_transfers(&self.db).await?;
        let now_unix = self.clock.now_unix();

        if let Some(m) = &self.metrics {
            m.in_flight_transfers.set(rows.len() as i64);
        }

        let mut touched = 0usize;
        for (transfer_id, endpoints) in rows {
            if endpoints.is_empty() {
                continue;
            }
            let mut updated = Vec::with_capacity(endpoints.len());
            for ep in endpoints {
                let prior_status = ep.health.as_ref().map(|h| h.status);
                let outcome = self.prober.probe(&ep).await;
                if let Some(m) = &self.metrics {
                    m.health_probes_total
                        .with_label_values(&[match outcome {
                            ProbeOutcome::Success => "success",
                            ProbeOutcome::Failure => "failure",
                        }])
                        .inc();
                }
                let next = fold_health(ep, outcome, now_unix);
                // Debouncer transition telemetry — only counts
                // a state flip once, not every probe at the same
                // state. `prior_status = None` means the endpoint
                // hadn't been probed before; treat the initial seed
                // as "not a transition" since it's synthetic.
                if let (Some(m), Some(prior)) = (&self.metrics, prior_status) {
                    let new_status = next.health.as_ref().map(|h| h.status);
                    if Some(prior) != new_status {
                        let direction = match new_status {
                            Some(HealthStatus::Healthy) => "to_healthy",
                            Some(HealthStatus::Unhealthy) => "to_unhealthy",
                            None => "to_unknown",
                        };
                        m.health_transitions_total
                            .with_label_values(&[direction])
                            .inc();
                    }
                }
                updated.push(next);
            }
            persist_reachable_at(&self.db, &transfer_id, &updated).await?;
            touched += 1;
        }
        Ok(touched)
    }
}

/// Fold a probe outcome into an endpoint's health state, returning a
/// new endpoint with updated `health`. A fresh endpoint with
/// `health: None` seeds itself as `fresh_healthy` before applying the
/// outcome — this is the first time the background monitor has seen
/// it, and the admission-time probe already proved it healthy once.
fn fold_health(mut ep: Endpoint, outcome: ProbeOutcome, now_unix: i64) -> Endpoint {
    let current = ep
        .health
        .take()
        .unwrap_or_else(|| EndpointHealth::fresh_healthy(now_unix));
    let next = match outcome {
        ProbeOutcome::Success => current.on_probe_success(now_unix),
        ProbeOutcome::Failure => current.on_probe_failure(now_unix),
    };
    ep.health = Some(next);
    ep
}

/// Fetch every transfer in `ready_for_pickup` state that carries a
/// non-empty `reachable_at[]`, along with its parsed endpoints. Caps
/// at 500 rows per tick so a large backlog can't blow out the prober
/// concurrency limits.
async fn load_in_flight_transfers(
    pool: &PgPool,
) -> Result<Vec<(String, Vec<Endpoint>)>, sqlx::Error> {
    let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
        r#"
        SELECT transfer_id, reachable_at
        FROM transfers
        WHERE state = 'ready_for_pickup'
          AND jsonb_array_length(reachable_at) > 0
        ORDER BY created_at ASC
        LIMIT 500
        "#,
    )
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(transfer_id, json)| {
            let eps: Vec<Endpoint> = serde_json::from_value(json).unwrap_or_default();
            (transfer_id, eps)
        })
        .collect())
}

/// Replace the transfer's `reachable_at[]` JSONB with the updated
/// endpoint list. The UPDATE is unconditional on state — the read
/// phase already filtered to `ready_for_pickup`, and a racing state
/// transition (e.g. the recipient picked up the transfer in the
/// microseconds between our SELECT and UPDATE) is harmless: writing
/// health metadata onto a `delivered` row doesn't break anything.
async fn persist_reachable_at(
    pool: &PgPool,
    transfer_id: &str,
    endpoints: &[Endpoint],
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_value(endpoints).expect("Endpoint serializes by construction");
    sqlx::query(
        r#"
        UPDATE transfers
        SET reachable_at = $2
        WHERE transfer_id = $1
        "#,
    )
    .bind(transfer_id)
    .bind(json)
    .execute(pool)
    .await?;
    Ok(())
}

/// Convenience: fold a single-endpoint `Endpoint` through the full
/// state machine with an arbitrary sequence of probe outcomes.
/// Exposed for unit tests so the end-to-end fold path is tested
/// without spinning a DB pool.
#[cfg(test)]
pub(crate) fn replay(endpoint: Endpoint, outcomes: &[ProbeOutcome], start_unix: i64) -> Endpoint {
    let mut ep = endpoint;
    for (i, o) in outcomes.iter().enumerate() {
        ep = fold_health(ep, *o, start_unix + i as i64);
    }
    ep
}

/// Returns true iff the endpoint's current health classification is
/// `Healthy`. Absent health is treated as healthy (freshly admitted).
#[allow(dead_code)]
pub fn is_healthy(ep: &Endpoint) -> bool {
    ep.health
        .as_ref()
        .map(|h| matches!(h.status, HealthStatus::Healthy))
        .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn ep() -> Endpoint {
        Endpoint::cloudflare_quick("https://x.trycloudflare.com")
    }

    #[test]
    fn fold_seeds_healthy_on_first_success() {
        let out = replay(ep(), &[ProbeOutcome::Success], 1_700_000_000);
        let h = out.health.expect("fold must populate health");
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(h.last_probe_unix, Some(1_700_000_000));
    }

    #[test]
    fn fold_flips_to_unhealthy_after_three_failures() {
        let out = replay(
            ep(),
            &[
                ProbeOutcome::Failure,
                ProbeOutcome::Failure,
                ProbeOutcome::Failure,
            ],
            0,
        );
        let h = out.health.unwrap();
        assert_eq!(h.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn fold_heals_after_two_successes_post_unhealthy() {
        let out = replay(
            ep(),
            &[
                ProbeOutcome::Failure,
                ProbeOutcome::Failure,
                ProbeOutcome::Failure, // now Unhealthy
                ProbeOutcome::Success,
                ProbeOutcome::Success, // two consecutive → Healthy
            ],
            0,
        );
        assert_eq!(out.health.unwrap().status, HealthStatus::Healthy);
    }

    #[test]
    fn is_healthy_treats_missing_health_as_healthy() {
        let ep = ep();
        assert!(
            is_healthy(&ep),
            "fresh endpoint with no health block is Healthy (admission-time probe already passed)"
        );
    }

    /// Scripted mock prober used by the tick-level unit test below and
    /// by the full integration test in `tests/health_monitor.rs`.
    pub(super) struct ScriptedProber {
        pub outcomes: Mutex<Vec<ProbeOutcome>>,
    }

    impl ScriptedProber {
        pub fn new(outcomes: Vec<ProbeOutcome>) -> Self {
            Self {
                outcomes: Mutex::new(outcomes),
            }
        }
    }

    #[async_trait]
    impl EndpointProber for ScriptedProber {
        async fn probe(&self, _endpoint: &Endpoint) -> ProbeOutcome {
            let mut g = self.outcomes.lock().unwrap();
            // Reuse the last entry if the script underflows — makes
            // "all-failure" and "all-success" scripts trivial to write.
            if g.len() > 1 {
                g.remove(0)
            } else {
                *g.first().unwrap_or(&ProbeOutcome::Success)
            }
        }
    }

    #[tokio::test]
    async fn scripted_prober_consumes_and_tails() {
        let p = ScriptedProber::new(vec![ProbeOutcome::Failure, ProbeOutcome::Success]);
        let ep = ep();
        assert_eq!(p.probe(&ep).await, ProbeOutcome::Failure);
        assert_eq!(p.probe(&ep).await, ProbeOutcome::Success);
        // Tail: script exhausted, subsequent calls repeat the last entry.
        assert_eq!(p.probe(&ep).await, ProbeOutcome::Success);
        assert_eq!(p.probe(&ep).await, ProbeOutcome::Success);
    }
}
