//! Compose multiple [`TunnelProvider`] instances into a single
//! transport-plurality layer.
//!
//! Per decision 1B of the Sprint 2 plan-eng-review (2026-04-21), each
//! provider keeps its single-URL surface; the orchestrator is the thing
//! that owns a `Vec<TransportEntry>` and exposes the union of their
//! reachable endpoints as `aex_core::Endpoint[]`.
//!
//! Per ADR-0019 the orchestrator degrades gracefully: if an individual
//! provider's `start()` fails, it's recorded as [`TransportStartOutcome::Failed`]
//! and the rest of the providers continue. Upstream formats the full
//! slice as the `AEX_TRANSPORTS_JSON=…` stdout line.

use aex_core::Endpoint;

use crate::provider::TunnelProvider;

/// One transport wired into [`TunnelOrchestrator`].
///
/// `kind` is the `aex_core::Endpoint::KIND_*` string that will appear
/// in `reachable_at[]` on the wire.
/// `priority` is the sender's preference — lower tries first on the
/// receiving side (ADR-0012). Ties break by insertion order.
pub struct TransportEntry {
    pub kind: String,
    pub priority: i32,
    pub provider: Box<dyn TunnelProvider>,
}

impl TransportEntry {
    pub fn new(kind: impl Into<String>, priority: i32, provider: Box<dyn TunnelProvider>) -> Self {
        Self {
            kind: kind.into(),
            priority,
            provider,
        }
    }
}

/// Outcome of starting one transport.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TransportStartOutcome {
    /// Transport came up. `url` is what the recipient will dial.
    Started {
        kind: String,
        url: String,
        priority: i32,
    },
    /// Transport failed to start; the rest of the orchestrator keeps
    /// going. `reason` surfaces verbatim in `AEX_TRANSPORTS_JSON`.
    Failed { kind: String, reason: String },
}

impl TransportStartOutcome {
    pub fn kind(&self) -> &str {
        match self {
            Self::Started { kind, .. } => kind,
            Self::Failed { kind, .. } => kind,
        }
    }
}

pub struct TunnelOrchestrator {
    entries: Vec<TransportEntry>,
    outcomes: Vec<TransportStartOutcome>,
}

impl TunnelOrchestrator {
    pub fn new(entries: Vec<TransportEntry>) -> Self {
        Self {
            entries,
            outcomes: Vec::new(),
        }
    }

    /// Start every provider against the same local port. Failures are
    /// recorded in the outcome vec and do not short-circuit the rest.
    pub async fn start_all(&mut self, local_port: u16) -> &[TransportStartOutcome] {
        self.outcomes.clear();
        for entry in self.entries.iter_mut() {
            match entry.provider.start(local_port).await {
                Ok(()) => match entry.provider.public_url() {
                    Some(url) => {
                        tracing::info!(
                            target: "aex_tunnel::orchestrator",
                            kind = %entry.kind,
                            url = %url,
                            "transport up"
                        );
                        self.outcomes.push(TransportStartOutcome::Started {
                            kind: entry.kind.clone(),
                            url,
                            priority: entry.priority,
                        });
                    }
                    None => {
                        let reason = "provider returned no public_url after start".to_string();
                        tracing::warn!(
                            target: "aex_tunnel::orchestrator",
                            kind = %entry.kind,
                            "{reason}"
                        );
                        self.outcomes.push(TransportStartOutcome::Failed {
                            kind: entry.kind.clone(),
                            reason,
                        });
                    }
                },
                Err(e) => {
                    let reason = e.to_string();
                    tracing::warn!(
                        target: "aex_tunnel::orchestrator",
                        kind = %entry.kind,
                        "transport failed to start: {reason}"
                    );
                    self.outcomes.push(TransportStartOutcome::Failed {
                        kind: entry.kind.clone(),
                        reason,
                    });
                }
            }
        }
        &self.outcomes
    }

    /// Stop every provider. Errors on individual providers are logged
    /// but never fail the whole call — orderly shutdown is best-effort.
    pub async fn stop_all(&mut self) {
        for entry in self.entries.iter_mut() {
            if let Err(e) = entry.provider.stop().await {
                tracing::warn!(
                    target: "aex_tunnel::orchestrator",
                    kind = %entry.kind,
                    "transport stop error: {e}"
                );
            }
        }
        self.outcomes.clear();
    }

    /// Successful-start outcomes projected into `aex_core::Endpoint`
    /// objects, sorted by sender priority then by entry order. This is
    /// what goes into `reachable_at[]` on the wire (ADR-0013).
    pub fn endpoints(&self) -> Vec<Endpoint> {
        let mut eps: Vec<(usize, &str, String, i32)> = self
            .outcomes
            .iter()
            .enumerate()
            .filter_map(|(idx, o)| match o {
                TransportStartOutcome::Started {
                    kind,
                    url,
                    priority,
                } => Some((idx, kind.as_str(), url.clone(), *priority)),
                TransportStartOutcome::Failed { .. } => None,
            })
            .collect();
        eps.sort_by_key(|(idx, _, _, prio)| (*prio, *idx));
        eps.into_iter()
            .map(|(_, kind, url, priority)| Endpoint {
                kind: kind.to_string(),
                url,
                priority,
                health_hint_unix: None,
            })
            .collect()
    }

    /// Full outcome slice, including failures. Used by the data-plane
    /// binary to emit `AEX_TRANSPORTS_JSON=…` on stdout (ADR-0019).
    pub fn outcomes(&self) -> &[TransportStartOutcome] {
        &self.outcomes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        provider::{TunnelProvider, TunnelStatus},
        stub::StubTunnel,
        TunnelError, TunnelResult,
    };
    use async_trait::async_trait;

    /// Provider that always fails `start()` — exercises the graceful
    /// degrade path of the orchestrator (ADR-0019).
    struct FailingProvider {
        reason: String,
    }

    #[async_trait]
    impl TunnelProvider for FailingProvider {
        async fn start(&mut self, _local_port: u16) -> TunnelResult<()> {
            Err(TunnelError::Other(self.reason.clone()))
        }
        async fn stop(&mut self) -> TunnelResult<()> {
            Ok(())
        }
        fn public_url(&self) -> Option<String> {
            None
        }
        fn status(&self) -> TunnelStatus {
            TunnelStatus::Disconnected {
                reason: self.reason.clone(),
            }
        }
    }

    #[tokio::test]
    async fn mixed_success_and_failure_collected() {
        let entries = vec![
            TransportEntry::new(
                Endpoint::KIND_CLOUDFLARE_QUICK,
                0,
                Box::new(StubTunnel::new("https://a.trycloudflare.com")),
            ),
            TransportEntry::new(
                Endpoint::KIND_IROH,
                1,
                Box::new(FailingProvider {
                    reason: "no relay configured".into(),
                }),
            ),
            TransportEntry::new(
                Endpoint::KIND_FRP,
                2,
                Box::new(StubTunnel::new("https://frp.example/x")),
            ),
        ];
        let mut orch = TunnelOrchestrator::new(entries);
        let outcomes = orch.start_all(8080).await;
        assert_eq!(outcomes.len(), 3);
        assert!(
            matches!(&outcomes[0], TransportStartOutcome::Started { kind, .. } if kind == "cloudflare_quick")
        );
        assert!(
            matches!(&outcomes[1], TransportStartOutcome::Failed { kind, .. } if kind == "iroh")
        );
        assert!(
            matches!(&outcomes[2], TransportStartOutcome::Started { kind, .. } if kind == "frp")
        );

        let eps = orch.endpoints();
        assert_eq!(eps.len(), 2, "failures excluded from endpoints()");
        assert_eq!(eps[0].kind, "cloudflare_quick");
        assert_eq!(eps[0].priority, 0);
        assert_eq!(eps[1].kind, "frp");
        assert_eq!(eps[1].priority, 2);

        orch.stop_all().await;
        assert!(orch.outcomes().is_empty());
    }

    #[tokio::test]
    async fn endpoints_sorted_by_priority_then_order() {
        let entries = vec![
            TransportEntry::new("a", 5, Box::new(StubTunnel::new("https://a"))),
            TransportEntry::new("b", 1, Box::new(StubTunnel::new("https://b"))),
            TransportEntry::new("c", 1, Box::new(StubTunnel::new("https://c"))),
        ];
        let mut orch = TunnelOrchestrator::new(entries);
        orch.start_all(0).await;
        let eps = orch.endpoints();
        let kinds: Vec<&str> = eps.iter().map(|e| e.kind.as_str()).collect();
        // priority 1 ties break by insertion order: b before c; then a.
        assert_eq!(kinds, vec!["b", "c", "a"]);
    }

    #[test]
    fn transport_start_outcome_serde() {
        let ok = TransportStartOutcome::Started {
            kind: "iroh".into(),
            url: "iroh:abc".into(),
            priority: 1,
        };
        let fail = TransportStartOutcome::Failed {
            kind: "iroh".into(),
            reason: "no relay".into(),
        };
        let json_ok = serde_json::to_string(&ok).unwrap();
        let json_fail = serde_json::to_string(&fail).unwrap();
        assert!(json_ok.contains(r#""state":"started""#));
        assert!(json_ok.contains(r#""kind":"iroh""#));
        assert!(json_fail.contains(r#""state":"failed""#));
        assert!(json_fail.contains(r#""reason":"no relay""#));
    }
}
