# ADR-0021: Endpoint health — asymmetric debounce (3 failures to unhealth, 2 successes to heal)

## Status

Accepted 2026-04-21.

## Context

The background re-validator (ADR-0014) periodically polls each
`reachable_at[]` endpoint. A single transient failure should not
downgrade a healthy endpoint (false negatives flap the state); a single
success on a long-broken endpoint shouldn't mark it healthy either
(false positives send transfers at a flapping endpoint). The right
answer is asymmetric: harder to mark healthy than to mark unhealthy,
because an unhealthy misclassification has a clean recovery path (try
next endpoint) while a healthy misclassification wastes a recipient's
connection attempt.

## Decision

Endpoint health transitions:

- **Healthy → Unhealthy:** after **3 consecutive failed probes**.
- **Unhealthy → Healthy:** after **2 consecutive successful probes**.

Probe interval is 30 s in-flight, 5 min at-rest. A freshly admitted
endpoint starts `Healthy` (it has just passed a fresh probe in
`verify_tunnel_http_healthz`).

## Consequences

- Transient network blips don't cause endpoint thrash.
- A genuinely broken endpoint goes unhealthy within 1–1.5 minutes.
- Recovery lag is 60 seconds (two probes at 30 s), acceptable.
- The health state is persisted in the `reachable_at[]` JSONB so it
  survives control-plane restarts.
