# AEX Architecture Decision Records

This directory is the log of **architectural and strategic decisions** for the
AEX protocol and its reference implementation. Every decision in the
"Network Sovereignty" 12-month plan (`.context/network-sovereignty-plan.md`,
approved 2026-04-21) is recorded here as a separate file.

## Why ADRs

When someone asks three months from now "why did we pick Iroh over
TailscaleFunnel for Sprint 2 primary transport?" or "why are we self-funded
rather than taking the NLnet grant upfront?", the answer should live in a
single canonical place — not in Slack history, not in a closed PR description,
not in a founder's head.

Each file below captures one decision with its context, the decision itself,
and its consequences. New decisions go in as new files; the existing files
are immutable once accepted (if a decision changes, write a new ADR that
supersedes it).

## Template

```markdown
# ADR-NNNN: Short decision title

## Status

Accepted YYYY-MM-DD.

## Context

What problem, constraint, or opportunity motivated this decision? Link to
prior ADRs if this one refines or depends on them.

## Decision

One or two sentences in active voice: "We will ... because ...".

## Consequences

What this decision makes easier, what it makes harder, what it rules out,
and what follow-up work it implies.
```

## Index

### Strategic (Q1–Q10, from plan "Decision matrix §Strategic")

| #    | Title |
|------|-------|
| [0001](0001-breaking-wire-v1-3-0-beta.md)       | Breaking wire `v1.3.0-beta.1`: `tunnel_url` → `reachable_at[]` |
| [0002](0002-iroh-first-class-transport.md)      | Iroh first-class transport from Sprint 2 |
| [0003](0003-fly-io-multi-process-colocation.md) | Fly.io multi-process co-location for control plane + DERP + TURNS |
| [0004](0004-go-sdk-phase-4-java-phase-5.md)     | Go SDK in Phase 4, Java SDK in Phase 5 |
| [0005](0005-compliance-internal-no-vanta.md)    | Internal compliance framework; customer-funded audit; no Vanta Y1 |
| [0006](0006-did-ethr-minimal-phase-4.md)        | DID:ethr minimal support in Phase 4; deeper integration only on adoption signal |
| [0007](0007-free-beta-then-paid-sep-2026.md)    | Free beta Jun–Sep 2026; paid tier Sep 2026; grandfather first 50 users |
| [0008](0008-zero-client-side-telemetry.md)      | Zero client-side telemetry, forever |
| [0009](0009-bsl-to-apache-conversion-q4.md)     | BSL-1.1 → Apache-2.0 conversion Q4 2026, pre-AAIF submission |
| [0010](0010-self-funded-plus-nlnet.md)          | Self-funded Year 1; optional NLnet grant application |

### Architecture (Issues 1–8)

| #    | Title |
|------|-------|
| [0011](0011-same-keypair-spize-and-iroh.md)     | Same Ed25519 keypair backs `spize:*` identity and Iroh NodeID |
| [0012](0012-transport-negotiation-sender-ranked-serial-sticky.md) | Sender-ranked, serial-fallback, sticky transport negotiation |
| [0013](0013-reachable-at-jsonb-column.md)       | `reachable_at[]` stored as a JSONB column, not a normalized table |
| [0014](0014-transport-validation-budget.md)     | Transport validation: at-least-1-healthy + 15 s budget + periodic re-validation |
| [0015](0015-iroh-pinned-with-fallback.md)       | Iroh pinned to `=0.96.0`, behind abstraction, with runtime fallback |
| [0016](0016-single-region-ams-derp.md)          | Single-region DERP (AMS), metric-gated expansion |
| [0017](0017-captive-portal-shared-crate.md)     | Captive-portal detection in a shared crate; multi-endpoint consensus; soft-warn |
| [0018](0018-wire-v1-frozen-capability-bits-v2-phase-6.md) | Wire v1 frozen; capability bits in Agent Card; v2 RFC at Phase 6 |

### Error handling & rescue (Issues 9–13)

| #    | Title |
|------|-------|
| [0019](0019-iroh-graceful-degrade.md)           | Iroh failures degrade gracefully with structured `AEX_TRANSPORTS_JSON` |
| [0020](0020-admin-blob-first-write-wins.md)     | `POST /admin/blob/:id` is first-write-wins; second write returns 409 |
| [0021](0021-endpoint-health-asymmetric-debouncing.md) | Endpoint health: asymmetric debounce (3 failures to unhealth, 2 successes to heal) |
| [0022](0022-stripe-webhook-transactional-inbox.md) | Stripe webhook: transactional inbox + idempotency key |
| [0023](0023-captive-portal-rich-error.md)       | Captive-portal rescue: rich error with actionable hint |

### Security (Issues 14–16)

| #    | Title |
|------|-------|
| [0024](0024-formal-key-rotation-v1-3.md)        | Formal `spize-rotate-key:v1` protocol in `v1.3.0-beta.1`; 24 h grace |
| [0025](0025-jws-signed-agent-card.md)           | JWS-signed `/.well-known/agent-card.json` |
| [0026](0026-jws-signed-did-web.md)              | JWS-signed `did:web` document with AEX extension proof block |

### Data flow (Issues 17–18)

| #    | Title |
|------|-------|
| [0027](0027-file-blob-source-atomic-rename.md)  | `FileBlobSource`: write-fsync-rename; rebuild-from-disk on startup; GC stale tmp |
| [0028](0028-relative-time-tickets-v1-time.md)   | Relative-time tickets (`issued_at` + `duration`) + `/v1/time` drift endpoint |

### Code quality (Issues 19–20)

| #    | Title |
|------|-------|
| [0029](0029-normative-spec-plus-conformance.md) | Normative spec (`docs/protocol-v1.md` §5) + per-language conformance suite + CI gate |
| [0030](0030-aex-net-crate-bounded-scope.md)     | `aex-net` crate scope: DNS + HTTP + retry + captive only |

### Tests (Issues 21–22)

| #    | Title |
|------|-------|
| [0031](0031-property-plus-scenario-plus-chaos.md)     | Layered testing: property (proptest) + scenario (mocks) + chaos (toxiproxy) |
| [0032](0032-fly-io-testbed-fuzz-golden-vectors.md)    | Dedicated Fly.io testbed + `cargo-fuzz` + golden vector JSON |

### Performance (Issue 23)

| #    | Title |
|------|-------|
| [0033](0033-global-semaphore-50-permits.md)     | Global 50-permit semaphore + backpressure + metrics |

### Observability (Issues 24–25)

| #    | Title |
|------|-------|
| [0034](0034-opentelemetry-everywhere.md)        | OpenTelemetry everywhere, Grafana Cloud free tier |
| [0035](0035-three-tier-alerts-plus-slo.md)      | 3-tier alerts (P1 page / P2 ticket / P3 info) + SLO + error budget |

### Deployment (Issue 26)

| #    | Title |
|------|-------|
| [0036](0036-coordinated-rollout-dual-wire.md)   | Coordinated rollout + desktop dual-wire + 30-day grace |

### Long-term (Issue 27)

| #    | Title |
|------|-------|
| [0037](0037-bcp-contributor-onramp-adr-log.md)  | Business continuity plan + contributor onramp + ADR log |
