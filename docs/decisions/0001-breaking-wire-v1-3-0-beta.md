# ADR-0001: Breaking wire `v1.3.0-beta.1`: `tunnel_url` → `reachable_at[]`

## Status

Accepted 2026-04-21.

## Context

The v1.2.0-alpha wire format announces a sender's data plane as a single
`tunnel_url` string. That works for Sprint 1's Cloudflare-only world but is
structurally unable to express the Sprint 2 goal of transport plurality —
multiple reachable endpoints of different kinds (Cloudflare, Iroh P2P,
Tailscale Funnel, FRP, DERP, TURNS) from which a recipient can pick the first
functioning one.

## Decision

We will bump the wire format to `v1.3.0-beta.1` at the end of Sprint 2 and
replace `tunnel_url: Option<String>` with `reachable_at: Vec<Endpoint>` where
`Endpoint` carries `kind`, `url`, `priority`, and a `health_hint` timestamp.
The change is breaking; the `v1.2.0-alpha.3` tag already pushed is frozen as a
git snapshot and not published. The next crates.io / npm / PyPI release is
`v1.3.0-beta.1`.

## Consequences

- Coordinated release: all crates, SDKs, and desktop bump in lockstep.
- Desktop Spize carries a dual-wire code path for 30 days (ADR-0036).
- The canonical signing bytes (`spize-transfer-intent`) gain the new field;
  the `v1` prefix remains since the wire is still under v1.x.
- No breaking change for callers who never set `tunnel_url` (M1 plain send).
