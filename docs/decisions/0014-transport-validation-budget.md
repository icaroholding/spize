# ADR-0014: Transport validation — at-least-1-healthy + 15 s budget + periodic re-validation

## Status

Accepted 2026-04-21.

## Context

The control plane must not issue a ticket pointing at a dead endpoint.
With `reachable_at[]` carrying several candidates, validating every one
before admitting the transfer is slow; validating none leaves recipients
chasing dead tunnels. We need a policy that is both correct and fast.

## Decision

On `send_via_tunnel`, the control plane validates endpoints in priority
order and admits the transfer as soon as **at least one** endpoint passes
a fresh `/healthz` probe. The total validation budget is **15 seconds**
wall-clock — if no endpoint passes in that window, the transfer is
rejected with a specific error. A background task re-validates admitted
transfers periodically (every 30 s until the transfer is picked up) so a
long-lived `ready_for_pickup` state doesn't mask a later endpoint failure.

## Consequences

- Best-case `send_via_tunnel` admits in <1 s when the first endpoint is
  healthy.
- Worst-case is a clean 15 s timeout instead of a 40 s pile-up of three
  10-second attempts (today's Sprint 1 behaviour).
- The periodic re-validator costs a handful of `/healthz` calls per
  in-flight transfer — negligible.
- Callers can distinguish "no reachable endpoint" from protocol errors
  without scraping retry logs.
