# ADR-0002: Iroh first-class transport from Sprint 2

## Status

Accepted 2026-04-21.

## Context

Sprint 1 shipped exclusively over Cloudflare Quick Tunnels. Any provider
outage, ToS change, or regional block takes AEX with it. Iroh gives us a
second, fundamentally different transport (QUIC over direct peer connect with
hole-punching, falling back to relay DERP when symmetric NAT prevents
direct). Adding it before the wire breaks (v1.3.0-beta.1) lets us ship
transport plurality in a single coordinated release.

## Decision

We will add `IrohTunnel` as a first-class transport alongside
`CloudflareQuickTunnel` in Sprint 2. Iroh will be pinned to `=0.96.0`
(see ADR-0015) and sit behind a transport abstraction so neither senders nor
recipients depend on its API surface directly. The sender ranks transports,
the recipient tries them serially with stickiness (ADR-0012).

## Consequences

- A new dependency with its own upgrade cycle and operational surface.
- DERP + TURNS infrastructure becomes necessary (ADR-0003, ADR-0016).
- The "Cloudflare or nothing" narrative goes away — we can ship on networks
  where Cloudflare is blocked or disfavored.
- Sprint 2 schedule has three new transport impls (Iroh, Named Cloudflare,
  Tailscale Funnel) plus FRP in the pipeline.
