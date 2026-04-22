//! End-to-end test for the background endpoint health loop
//! (ADR-0014 + ADR-0021).
//!
//! Drives `HealthMonitor::tick` directly with a scripted mock prober
//! against a real Postgres database: seeds a transfer with a
//! `reachable_at[]` endpoint, runs the expected number of ticks,
//! reads back the persisted JSONB and asserts the debouncer flipped
//! at exactly the right boundary.
//!
//! Requires `DATABASE_URL` to point at a live Postgres instance.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::json;
use sqlx::PgPool;

use aex_control_plane::clock::{Clock, FrozenClock};
use aex_control_plane::health_monitor::{EndpointProber, HealthMonitor, ProbeOutcome};
use aex_core::{Endpoint, HealthStatus};

/// Scripted prober: consumes the outcome queue front-to-back, repeats
/// the last entry once the script is exhausted.
struct ScriptedProber {
    outcomes: Mutex<Vec<ProbeOutcome>>,
    calls: Mutex<usize>,
}

impl ScriptedProber {
    fn new(outcomes: Vec<ProbeOutcome>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes),
            calls: Mutex::new(0),
        }
    }

    fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

#[async_trait]
impl EndpointProber for ScriptedProber {
    async fn probe(&self, _endpoint: &Endpoint) -> ProbeOutcome {
        *self.calls.lock().unwrap() += 1;
        let mut g = self.outcomes.lock().unwrap();
        if g.len() > 1 {
            g.remove(0)
        } else {
            *g.first().unwrap_or(&ProbeOutcome::Success)
        }
    }
}

async fn seed_transfer(pool: &PgPool, transfer_id: &str) {
    // The full transfer insert path goes through an agent_id that
    // must exist in `agents`. Bypass the FK pressure here by using
    // the raw insert directly — we only care about reachable_at.
    let reachable_at = json!([{
        "kind": "cloudflare_quick",
        "url": "https://x.trycloudflare.com",
        "priority": 0
    }]);
    sqlx::query(
        r#"
        INSERT INTO transfers (
            transfer_id, sender_agent_id, recipient, recipient_kind,
            state, size_bytes, tunnel_url, reachable_at
        ) VALUES ($1, 'spize:acme/alice:aabbcc', 'spize:acme/bob:ddeeff',
                  'spize_native', 'ready_for_pickup', 1024,
                  'https://x.trycloudflare.com', $2)
        "#,
    )
    .bind(transfer_id)
    .bind(reachable_at)
    .execute(pool)
    .await
    .expect("seed transfer");
}

async fn read_reachable_at(pool: &PgPool, transfer_id: &str) -> Vec<Endpoint> {
    let (json,): (serde_json::Value,) =
        sqlx::query_as("SELECT reachable_at FROM transfers WHERE transfer_id = $1")
            .bind(transfer_id)
            .fetch_one(pool)
            .await
            .expect("fetch reachable_at");
    serde_json::from_value(json).expect("decode reachable_at")
}

#[sqlx::test]
async fn tick_marks_endpoint_unhealthy_after_three_failures(pool: PgPool) {
    seed_transfer(&pool, "tx_fail_three").await;

    let prober = Arc::new(ScriptedProber::new(vec![ProbeOutcome::Failure]));
    let clock: Arc<dyn Clock> = Arc::new(FrozenClock::new(1_800_000_000));
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let monitor = HealthMonitor::new(pool.clone(), prober.clone(), clock.clone(), rx);

    // 1st tick: one failure folded into a fresh endpoint.
    assert_eq!(monitor.tick().await.unwrap(), 1);
    let eps = read_reachable_at(&pool, "tx_fail_three").await;
    assert_eq!(eps.len(), 1);
    let h = eps[0]
        .health
        .as_ref()
        .expect("health populated after 1 tick");
    assert_eq!(
        h.status,
        HealthStatus::Healthy,
        "1 failure: still Healthy — debouncer hasn't tripped yet"
    );
    assert_eq!(h.consecutive_fails, 1);

    // 2nd tick.
    monitor.tick().await.unwrap();
    let eps = read_reachable_at(&pool, "tx_fail_three").await;
    assert_eq!(
        eps[0].health.as_ref().unwrap().status,
        HealthStatus::Healthy
    );

    // 3rd tick: the debouncer flips.
    monitor.tick().await.unwrap();
    let eps = read_reachable_at(&pool, "tx_fail_three").await;
    assert_eq!(
        eps[0].health.as_ref().unwrap().status,
        HealthStatus::Unhealthy,
        "3 consecutive failures MUST flip the endpoint to Unhealthy (ADR-0021)"
    );
    assert_eq!(prober.call_count(), 3);
}

#[sqlx::test]
async fn tick_heals_endpoint_after_two_successes(pool: PgPool) {
    seed_transfer(&pool, "tx_heal_two").await;

    // Script: 3 failures (→ Unhealthy), then repeated Success (→ Healthy after 2).
    let prober = Arc::new(ScriptedProber::new(vec![
        ProbeOutcome::Failure,
        ProbeOutcome::Failure,
        ProbeOutcome::Failure,
        ProbeOutcome::Success,
        ProbeOutcome::Success,
    ]));
    let clock: Arc<dyn Clock> = Arc::new(FrozenClock::new(1_800_000_000));
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let monitor = HealthMonitor::new(pool.clone(), prober, clock, rx);

    for _ in 0..3 {
        monitor.tick().await.unwrap();
    }
    assert_eq!(
        read_reachable_at(&pool, "tx_heal_two").await[0]
            .health
            .as_ref()
            .unwrap()
            .status,
        HealthStatus::Unhealthy
    );

    // 1 success — still Unhealthy (need 2 consecutive).
    monitor.tick().await.unwrap();
    assert_eq!(
        read_reachable_at(&pool, "tx_heal_two").await[0]
            .health
            .as_ref()
            .unwrap()
            .status,
        HealthStatus::Unhealthy
    );

    // 2nd success — flip to Healthy.
    monitor.tick().await.unwrap();
    assert_eq!(
        read_reachable_at(&pool, "tx_heal_two").await[0]
            .health
            .as_ref()
            .unwrap()
            .status,
        HealthStatus::Healthy,
        "2 consecutive successes MUST heal the endpoint (ADR-0021)"
    );
}

#[sqlx::test]
async fn tick_ignores_non_ready_for_pickup_transfers(pool: PgPool) {
    // Seed a transfer in `delivered` state — monitor should skip it.
    sqlx::query(
        r#"
        INSERT INTO transfers (
            transfer_id, sender_agent_id, recipient, recipient_kind,
            state, size_bytes, tunnel_url, reachable_at
        ) VALUES ('tx_delivered', 'spize:acme/alice:aabbcc',
                  'spize:acme/bob:ddeeff', 'spize_native', 'delivered',
                  1024, 'https://x.trycloudflare.com',
                  '[{"kind":"cloudflare_quick","url":"https://x.trycloudflare.com","priority":0}]'::jsonb)
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    let prober = Arc::new(ScriptedProber::new(vec![ProbeOutcome::Failure]));
    let clock: Arc<dyn Clock> = Arc::new(FrozenClock::new(1_800_000_000));
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let monitor = HealthMonitor::new(pool, prober.clone(), clock, rx);

    assert_eq!(
        monitor.tick().await.unwrap(),
        0,
        "delivered transfers must not be probed"
    );
    assert_eq!(
        prober.call_count(),
        0,
        "the mock prober must never be called when there is nothing in-flight"
    );
}

#[sqlx::test]
async fn tick_updates_last_probe_unix_from_clock(pool: PgPool) {
    seed_transfer(&pool, "tx_clock_check").await;
    let prober = Arc::new(ScriptedProber::new(vec![ProbeOutcome::Success]));
    let frozen = Arc::new(FrozenClock::new(1_900_000_000));
    let clock: Arc<dyn Clock> = frozen.clone();
    let (_tx, rx) = tokio::sync::watch::channel(false);
    let monitor = HealthMonitor::new(pool.clone(), prober, clock, rx);

    monitor.tick().await.unwrap();
    let eps = read_reachable_at(&pool, "tx_clock_check").await;
    assert_eq!(
        eps[0].health.as_ref().unwrap().last_probe_unix,
        Some(1_900_000_000),
        "last_probe_unix must come from the injected Clock, not the wall clock"
    );

    // Advance time and re-probe: the timestamp moves with the clock.
    frozen.advance(Duration::from_secs(30));
    monitor.tick().await.unwrap();
    let eps = read_reachable_at(&pool, "tx_clock_check").await;
    assert_eq!(
        eps[0].health.as_ref().unwrap().last_probe_unix,
        Some(1_900_000_030)
    );
}
