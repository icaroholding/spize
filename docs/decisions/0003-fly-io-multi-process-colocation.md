# ADR-0003: Fly.io multi-process co-location for control plane + DERP + TURNS

## Status

Accepted 2026-04-21.

## Context

Once Iroh enters the picture (ADR-0002) we need DERP relay and TURNS for the
cases where direct peer connect fails. Operating each as an independent
Fly.io app means three deploy pipelines, three sets of secrets, and three
things the founder has to remember to monitor. Fly.io supports multi-process
apps (`processes.app`, `processes.derp`, `processes.turns`) that share a
billing unit and lifecycle.

## Decision

We will run `aex-control-plane`, `derp`, and `turns` inside a single Fly.io
app as separate processes. Region AMS first (ADR-0016), metric-gated
expansion later. Secrets, cert material, and Postgres connection strings are
owned by the app, not a surrounding orchestration layer.

## Consequences

- One deploy, one rollback, one set of Sentry-style alerts.
- Coupled release cycle: a control-plane bump also restarts DERP / TURNS.
  Acceptable because these are small stateless programs.
- Single IP reputation; if one process misbehaves, peer networks that
  rate-limit by IP bucket all three together.
- `flyctl deploy` time grows with the biggest process; keep `derp` and
  `turns` as thin binaries to avoid slowing control-plane deploys.
