# ADR-0033: Global 50-permit semaphore + backpressure + metrics

## Status

Accepted 2026-04-21.

## Context

A control plane that enthusiastically accepts every concurrent transfer
ends up doing all of them slowly, or worse, running the host out of
socket FDs / memory. A bound is necessary. Choosing the bound is a
calibration matter; starting simple and measuring is better than
over-engineering a dynamic knob that isn't needed at Y1 scale.

## Decision

The control plane holds a global `tokio::sync::Semaphore` with **50
permits**. Transfer admission paths (`send_via_tunnel`,
`verify_tunnel_http_healthz`, tunnel health re-validation) acquire a
permit before issuing outbound traffic. Exhaustion returns HTTP **429
Too Many Requests** with a `Retry-After` header. Permit acquire /
release is surfaced as a Prometheus gauge.

## Consequences

- A traffic spike is handled gracefully: the 51st request waits up to
  a configurable timeout, then 429s — no runaway socket usage.
- The metric lets us calibrate the right permit count for the observed
  workload before Phase 3.
- Backpressure surfaces to SDKs as a retriable 429 (see §5.1 retry
  policy).
- Ceiling raised via env var without a code change when the observed
  workload clearly justifies it.
