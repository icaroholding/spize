//! `Endpoint` — a single way a recipient can reach a sender's data plane.
//!
//! Endpoints carry an optional [`EndpointHealth`] block populated by the
//! control plane's background re-validator (ADR-0014 + ADR-0021). The
//! health machine is asymmetric: three consecutive failed probes flip an
//! endpoint to `Unhealthy`, but two consecutive successes are required
//! to flip it back to `Healthy`. Freshly admitted endpoints start
//! `Healthy` because the admission flow in `aex-control-plane` already
//! proved them reachable once.
//!
//!
//! Introduced in Sprint 2 for transport plurality (`v1.3.0-beta.1`).
//! A transfer carries a list of endpoints (`reachable_at[]`); the recipient
//! SDK tries them in the sender's declared priority order per ADR-0012
//! (sender-ranked, serial, sticky) and stops at the first that works.
//!
//! ```text
//!     reachable_at[] (JSONB on transfers, JSON on the wire)
//!         │
//!         ├── { kind: "cloudflare_quick", url: "https://x.trycloudflare.com", priority: 0 }
//!         ├── { kind: "iroh",              url: "iroh:NodeID@relay:443",        priority: 1 }
//!         └── { kind: "frp",               url: "https://frp.example.com/x",    priority: 2 }
//!              │
//!              └── recipient tries in priority order, sticks with first success
//! ```
//!
//! ## Forward compatibility
//!
//! `kind` is a `String`, not an enum, so unknown kinds from a newer peer
//! are preserved losslessly. Recipients MUST skip endpoints whose `kind`
//! is not in [`Endpoint::KNOWN_KINDS`] rather than erroring. This mirrors
//! the capability-bit philosophy in ADR-0018 — new transports land
//! additively without requiring a wire bump.

use serde::{Deserialize, Serialize};

/// A single way to reach a sender's data plane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// Transport kind. See [`Endpoint::KIND_*`] constants for known values.
    /// Unknown values are preserved but MUST be skipped by recipients.
    pub kind: String,
    /// Reachable address. Schema is transport-specific:
    /// - `cloudflare_quick`, `cloudflare_named`, `tailscale_funnel`, `frp`: `https://host/...`
    /// - `iroh`: `iroh:<NodeID>@<relay_host>:<port>`
    pub url: String,
    /// Sender's preference (lower = try first). Ties broken by array order.
    #[serde(default)]
    pub priority: i32,
    /// Optional last-known-good timestamp (Unix seconds) used by the control
    /// plane's health cache. Absent on fresh endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_hint_unix: Option<i64>,
    /// Background-validator health state (ADR-0014, ADR-0021). Absent
    /// on wire payloads sent by clients; populated by the control
    /// plane after the first re-probe cycle. Recipients SHOULD skip
    /// endpoints whose `health.status` is `Unhealthy`; SDKs that don't
    /// recognise this field are forward-compatible because `health` is
    /// additive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<EndpointHealth>,
}

/// Persisted health state for a single [`Endpoint`]. Kept inline in
/// the `reachable_at` JSONB so a control-plane restart doesn't reset
/// the debounce counters; this means a flapping endpoint that was
/// about to flip `Unhealthy` keeps its accrued failure count across
/// deploys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointHealth {
    pub status: HealthStatus,
    /// Count of consecutive failed probes since the last success.
    /// Caps at [`EndpointHealth::FAIL_THRESHOLD`] (any higher is
    /// irrelevant — the endpoint is already `Unhealthy`).
    #[serde(default)]
    pub consecutive_fails: u8,
    /// Count of consecutive successful probes since the last failure.
    /// Caps at [`EndpointHealth::SUCCESS_THRESHOLD`].
    #[serde(default)]
    pub consecutive_successes: u8,
    /// Unix seconds of the most recent probe attempt. `None` if the
    /// background monitor hasn't run yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_probe_unix: Option<i64>,
}

/// Current health classification of an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    Healthy,
    Unhealthy,
}

impl EndpointHealth {
    /// Consecutive failures required to flip `Healthy → Unhealthy`
    /// (ADR-0021).
    pub const FAIL_THRESHOLD: u8 = 3;
    /// Consecutive successes required to flip `Unhealthy → Healthy`
    /// (ADR-0021). Deliberately higher friction than the failure
    /// threshold — a flapping endpoint should not race a recipient's
    /// connection attempt.
    pub const SUCCESS_THRESHOLD: u8 = 2;

    /// Initial health for an endpoint just admitted by the CP's
    /// admission-time `/healthz` probe.
    pub fn fresh_healthy(now_unix: i64) -> Self {
        Self {
            status: HealthStatus::Healthy,
            consecutive_fails: 0,
            consecutive_successes: 0,
            last_probe_unix: Some(now_unix),
        }
    }

    /// Fold a successful probe into this state. Returns `self` for
    /// ergonomic `fold`/`for` reassignment in loops.
    pub fn on_probe_success(mut self, now_unix: i64) -> Self {
        self.last_probe_unix = Some(now_unix);
        self.consecutive_fails = 0;
        // Saturating add so we never wrap around at u8::MAX.
        self.consecutive_successes = self.consecutive_successes.saturating_add(1);
        if matches!(self.status, HealthStatus::Unhealthy)
            && self.consecutive_successes >= Self::SUCCESS_THRESHOLD
        {
            self.status = HealthStatus::Healthy;
            self.consecutive_successes = 0;
        }
        // Cap the counter at the threshold once we're Healthy to keep
        // the on-wire JSON small and bounded.
        if matches!(self.status, HealthStatus::Healthy)
            && self.consecutive_successes > Self::SUCCESS_THRESHOLD
        {
            self.consecutive_successes = Self::SUCCESS_THRESHOLD;
        }
        self
    }

    /// Fold a failed probe into this state.
    pub fn on_probe_failure(mut self, now_unix: i64) -> Self {
        self.last_probe_unix = Some(now_unix);
        self.consecutive_successes = 0;
        self.consecutive_fails = self.consecutive_fails.saturating_add(1);
        if matches!(self.status, HealthStatus::Healthy)
            && self.consecutive_fails >= Self::FAIL_THRESHOLD
        {
            self.status = HealthStatus::Unhealthy;
            self.consecutive_fails = 0;
        }
        if matches!(self.status, HealthStatus::Unhealthy)
            && self.consecutive_fails > Self::FAIL_THRESHOLD
        {
            self.consecutive_fails = Self::FAIL_THRESHOLD;
        }
        self
    }

    /// True iff the endpoint is currently classified `Healthy`.
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, HealthStatus::Healthy)
    }
}

impl Endpoint {
    /// Cloudflare Quick Tunnel (`*.trycloudflare.com`, ephemeral).
    pub const KIND_CLOUDFLARE_QUICK: &'static str = "cloudflare_quick";
    /// Cloudflare Named Tunnel (`*.workers.dev` or custom hostname, persistent).
    pub const KIND_CLOUDFLARE_NAMED: &'static str = "cloudflare_named";
    /// Iroh peer-to-peer with DERP relay fallback.
    pub const KIND_IROH: &'static str = "iroh";
    /// Tailscale Funnel (public hostname on a tailnet).
    pub const KIND_TAILSCALE_FUNNEL: &'static str = "tailscale_funnel";
    /// FRP self-hosted reverse proxy.
    pub const KIND_FRP: &'static str = "frp";

    /// All kinds this crate knows how to reach. Adding a new transport in a
    /// later sprint adds a constant here + extends this array.
    pub const KNOWN_KINDS: &'static [&'static str] = &[
        Self::KIND_CLOUDFLARE_QUICK,
        Self::KIND_CLOUDFLARE_NAMED,
        Self::KIND_IROH,
        Self::KIND_TAILSCALE_FUNNEL,
        Self::KIND_FRP,
    ];

    /// True if `self.kind` is in [`Self::KNOWN_KINDS`]. Recipients use this
    /// to skip forward-incompatible endpoints without failing the transfer.
    pub fn is_known_kind(&self) -> bool {
        Self::KNOWN_KINDS.contains(&self.kind.as_str())
    }

    /// Convenience: Cloudflare Quick Tunnel endpoint at priority 0.
    pub fn cloudflare_quick(url: impl Into<String>) -> Self {
        Self {
            kind: Self::KIND_CLOUDFLARE_QUICK.into(),
            url: url.into(),
            priority: 0,
            health_hint_unix: None,
            health: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_quick_builder() {
        let e = Endpoint::cloudflare_quick("https://foo.trycloudflare.com");
        assert_eq!(e.kind, "cloudflare_quick");
        assert_eq!(e.url, "https://foo.trycloudflare.com");
        assert_eq!(e.priority, 0);
        assert!(e.is_known_kind());
    }

    #[test]
    fn unknown_kind_preserved_and_flagged() {
        let e = Endpoint {
            kind: "future_transport_v9".into(),
            url: "future:alien@mars:443".into(),
            priority: 5,
            health_hint_unix: None,
            health: None,
        };
        assert!(!e.is_known_kind());
    }

    #[test]
    fn serde_roundtrip_minimal() {
        let original = Endpoint::cloudflare_quick("https://x.trycloudflare.com");
        let json = serde_json::to_string(&original).unwrap();
        // Priority 0 is the default but explicit in serialization; health_hint absent.
        assert!(json.contains(r#""kind":"cloudflare_quick""#));
        assert!(json.contains(r#""url":"https://x.trycloudflare.com""#));
        assert!(!json.contains("health_hint_unix"));
        let back: Endpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn serde_roundtrip_with_health_hint() {
        let original = Endpoint {
            kind: Endpoint::KIND_IROH.into(),
            url: "iroh:abc123@relay.aex.dev:443".into(),
            priority: 1,
            health_hint_unix: Some(1_700_000_000),
            health: None,
        };
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains(r#""health_hint_unix":1700000000"#));
        let back: Endpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn endpoint_health_fresh_is_healthy() {
        let h = EndpointHealth::fresh_healthy(1_700_000_000);
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(h.consecutive_fails, 0);
        assert_eq!(h.consecutive_successes, 0);
        assert_eq!(h.last_probe_unix, Some(1_700_000_000));
    }

    #[test]
    fn health_flips_to_unhealthy_after_three_fails() {
        let mut h = EndpointHealth::fresh_healthy(0);
        h = h.on_probe_failure(1);
        assert_eq!(h.status, HealthStatus::Healthy, "1 fail: still healthy");
        h = h.on_probe_failure(2);
        assert_eq!(h.status, HealthStatus::Healthy, "2 fails: still healthy");
        h = h.on_probe_failure(3);
        assert_eq!(
            h.status,
            HealthStatus::Unhealthy,
            "3rd fail must flip to unhealthy"
        );
        assert_eq!(h.last_probe_unix, Some(3));
    }

    #[test]
    fn health_stays_unhealthy_after_one_success() {
        let mut h = EndpointHealth {
            status: HealthStatus::Unhealthy,
            consecutive_fails: 0,
            consecutive_successes: 0,
            last_probe_unix: Some(0),
        };
        h = h.on_probe_success(1);
        assert_eq!(
            h.status,
            HealthStatus::Unhealthy,
            "1 success is not enough to heal"
        );
        assert_eq!(h.consecutive_successes, 1);
    }

    #[test]
    fn health_heals_after_two_successes() {
        let mut h = EndpointHealth {
            status: HealthStatus::Unhealthy,
            consecutive_fails: 2,
            consecutive_successes: 0,
            last_probe_unix: Some(0),
        };
        h = h.on_probe_success(1);
        h = h.on_probe_success(2);
        assert_eq!(h.status, HealthStatus::Healthy);
        assert_eq!(
            h.consecutive_fails, 0,
            "healing must reset the fail counter"
        );
        assert_eq!(
            h.consecutive_successes, 0,
            "counter resets after a flip so the state machine is fresh again"
        );
    }

    #[test]
    fn success_resets_fail_counter_without_flipping() {
        // Two fails accrued but not three → still Healthy. A fresh
        // success must wipe the counter so a later 3rd fail doesn't
        // unfairly stack with the old ones.
        let mut h = EndpointHealth::fresh_healthy(0);
        h = h.on_probe_failure(1);
        h = h.on_probe_failure(2);
        assert_eq!(h.consecutive_fails, 2);
        h = h.on_probe_success(3);
        assert_eq!(h.consecutive_fails, 0);
        assert_eq!(h.status, HealthStatus::Healthy);
    }

    #[test]
    fn failure_resets_success_counter() {
        // Mid-heal (one success accrued) then a fail drops us back to
        // zero successes — healing must be two consecutive.
        let mut h = EndpointHealth {
            status: HealthStatus::Unhealthy,
            consecutive_fails: 0,
            consecutive_successes: 1,
            last_probe_unix: Some(0),
        };
        h = h.on_probe_failure(1);
        assert_eq!(h.consecutive_successes, 0);
        assert_eq!(h.status, HealthStatus::Unhealthy);
    }

    #[test]
    fn counters_are_saturated_not_wrapping() {
        // A healthy endpoint that has survived many probes must not
        // wrap the u8 success counter — we cap at the threshold.
        let mut h = EndpointHealth::fresh_healthy(0);
        for i in 1..=10 {
            h = h.on_probe_success(i);
        }
        assert!(h.consecutive_successes <= EndpointHealth::SUCCESS_THRESHOLD);
        assert_eq!(h.status, HealthStatus::Healthy);
    }

    #[test]
    fn health_round_trips_through_json() {
        let h = EndpointHealth {
            status: HealthStatus::Unhealthy,
            consecutive_fails: 3,
            consecutive_successes: 0,
            last_probe_unix: Some(1_700_000_000),
        };
        let json = serde_json::to_string(&h).unwrap();
        // Status lowercase for human-readable JSONB.
        assert!(json.contains(r#""status":"unhealthy""#));
        let back: EndpointHealth = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn deserialize_preserves_unknown_kind() {
        let json = r#"{"kind":"unknown_transport","url":"x://y","priority":9}"#;
        let e: Endpoint = serde_json::from_str(json).unwrap();
        assert_eq!(e.kind, "unknown_transport");
        assert!(!e.is_known_kind());
    }

    #[test]
    fn priority_defaults_to_zero_when_missing() {
        let json = r#"{"kind":"cloudflare_quick","url":"https://x.trycloudflare.com"}"#;
        let e: Endpoint = serde_json::from_str(json).unwrap();
        assert_eq!(e.priority, 0);
        assert_eq!(e.health_hint_unix, None);
    }

    #[test]
    fn known_kinds_covers_sprint_2_transports() {
        for k in [
            Endpoint::KIND_CLOUDFLARE_QUICK,
            Endpoint::KIND_CLOUDFLARE_NAMED,
            Endpoint::KIND_IROH,
            Endpoint::KIND_TAILSCALE_FUNNEL,
            Endpoint::KIND_FRP,
        ] {
            assert!(Endpoint::KNOWN_KINDS.contains(&k), "kind {k} missing");
        }
    }
}
