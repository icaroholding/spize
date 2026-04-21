# ADR-0015: Iroh pinned to `=0.96.0`, behind abstraction, with runtime fallback

## Status

Accepted 2026-04-21.

## Context

Iroh is a fast-moving dependency. Taking a caret range (`^0.96`) means
every patch release can ship behaviour changes in the transport layer — not
acceptable for a protocol whose wire format is frozen. But pinning to
exactly one version creates maintenance drag. And however much we trust
Iroh, it's a single point of failure for the P2P transport.

## Decision

`iroh = "=0.96.0"` — exact pin. All Iroh usage is hidden behind an `IrohTunnel`
struct implementing our `TunnelProvider` trait; no consumer of AEX sees
`iroh::*` types in its own API surface. On runtime, if `IrohTunnel::start`
fails or a dial-to-peer fails with a transport error, the recipient falls
back to the next entry in `reachable_at[]` (ADR-0012) automatically.

## Consequences

- Bumping Iroh is a deliberate, documented event that goes through its own
  ADR.
- If Iroh 0.97 breaks something subtly, we find out before consumers.
- The abstraction layer costs ~200 LOC in `aex-tunnel`; acceptable.
- Runtime fallback means a user with three transports declared can lose
  Iroh entirely and still transfer — the protocol stays up.
