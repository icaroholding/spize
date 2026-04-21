# ADR-0019: Iroh failures degrade gracefully with structured `AEX_TRANSPORTS_JSON`

## Status

Accepted 2026-04-21.

## Context

When `IrohTunnel::start` fails (missing dependencies, misconfigured DERP,
OS-level limitations), the data-plane binary today would crash. With
`reachable_at[]` and fallback (ADR-0012, ADR-0015) this becomes a soft
failure — the binary simply doesn't advertise Iroh in its endpoint list.
Orchestrators need a way to know *which* transports came up and which
didn't, so they can alert or surface the information to the operator.

## Decision

When a transport impl fails to initialize, the data-plane binary logs the
failure and continues with the remaining transports. It emits a
`AEX_TRANSPORTS_JSON=<json>` line on stdout after the `AEX_READY=1` line,
carrying a structured summary of the transports that came up and the
reasons for those that didn't (Delight #2).

## Consequences

- A single misconfigured transport never kills the binary.
- Orchestrators can parse the JSON to surface `Iroh: unavailable (no
  relay)` to users deterministically.
- Adding a new transport in future sprints is additive — it appears in
  the JSON with its own success / failure state without further wiring.
- Log noise: one extra stdout line per startup, small enough to not
  matter.
