# ADR-0018: Wire v1 frozen; capability bits in Agent Card; v2 RFC at Phase 6

## Status

Accepted 2026-04-21.

## Context

Protocol evolution needs two properties: stability (old clients don't
break) and extensibility (new features can ship). Freezing v1 after
v1.3.0-beta.1 and channeling all future capability hints through a
`capabilities` bit-vector in the agent card gives us that — new features
are discovered, not parsed from a bumped major version. A formal v2 gets
dedicated RFC process when the accumulated capability changes justify it.

## Decision

Once `v1.3.0-beta.1` ships, the wire format is frozen for the v1.x line.
New features land as capability bits advertised in the JWS-signed Agent
Card (ADR-0025); clients pick what they support. A separate v2 RFC
process starts at Phase 6 (Q1 2027 late), public and multi-stakeholder.

## Consequences

- No mid-v1 breaking change pressure — everything new hides behind
  capability bits.
- Agent Card grows a `capabilities: ["encrypted-at-rest", "streaming",
  …]` field that must be enumerable and documented.
- v2 process starts only after the protocol has a year of wire-frozen
  production experience to draw from.
- Early adopters get a stable target for the full v1.x duration.
