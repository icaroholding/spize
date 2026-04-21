# ADR-0028: Relative-time tickets (`issued_at` + `duration`) + `/v1/time` drift endpoint

## Status

Accepted 2026-04-21.

## Context

Data-plane tickets today carry an absolute `expires` Unix timestamp.
When the data-plane binary and the control plane have meaningfully
different clocks (seen on ephemeral container hosts with no NTP), a
ticket that was "valid for 60 s" can present as "already expired" on
arrival. Making the expiration relative to `issued_at` and letting the
verifier reconcile against its own clock eliminates the foot-gun.

## Decision

Tickets carry `issued_at: u64` + `duration_secs: u32` instead of a
computed `expires`. The verifier computes
`valid = now() ∈ [issued_at - skew, issued_at + duration_secs + skew]`
where `skew` is ±30 s. A new endpoint `GET /v1/time` returns the control
plane's wall clock so orchestrators can measure drift and alert.

## Consequences

- `/v1/time` becomes a supported endpoint with its own SLA (ADR-0034).
- Clients that used the old absolute `expires` break at the v1.3 wire
  bump — acceptable, coordinated rollout (ADR-0036).
- Audit log stores `issued_at` + `duration` as separate fields to aid
  later drift analysis.
- Time-machine attacks (reuse of a leaked ticket across clock skew
  exploits) get the same 30 s bound they had before.
