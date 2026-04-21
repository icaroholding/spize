# ADR-0012: Sender-ranked, serial-fallback, sticky transport negotiation

## Status

Accepted 2026-04-21.

## Context

Once `reachable_at[]` is live (ADR-0001) the recipient has multiple
endpoints to pick from. We could try them in parallel (fastest-wins) or
serial (deterministic). Parallel saves a few seconds on degraded networks
but makes audit trails non-deterministic and surfaces weird race conditions
when two transports both work. Sender ordering matters because the sender
knows which transport is cheapest and most reliable *for them*.

## Decision

The sender orders `reachable_at[]` by preference (most-preferred first).
The recipient tries entries serially until one succeeds, then sticks with
that choice for the duration of the transfer (no mid-fetch switching).
Subsequent transfers re-evaluate from the top — stickiness is per-transfer,
not per-peer.

## Consequences

- Audit logs unambiguously say which transport moved each transfer.
- A degraded first-choice transport delays every new transfer by its
  failure detection time (see ADR-0014 for budget).
- Sender keeps the priority knob — if a sender wants to prefer Iroh over
  Cloudflare, they put Iroh first, done.
- No in-flight fallback reduces complexity significantly; the recipient
  doesn't need to maintain partial-transfer state across transports.
