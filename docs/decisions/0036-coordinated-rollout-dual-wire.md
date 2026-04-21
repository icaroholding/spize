# ADR-0036: Coordinated rollout + desktop dual-wire + 30-day grace

## Status

Accepted 2026-04-21.

## Context

The `v1.3.0-beta.1` breaking wire change (ADR-0001) touches the control
plane, both SDKs, the MCP server, and Spize Desktop. Shipping them in
an unordered cascade means at least one combination in the wild is
broken on any given day. The fix is a coordinated rollout: everything
tagged together, with the control plane and desktop carrying a
temporary compatibility layer so users don't hit a hard cliff.

## Decision

The `v1.3.0-beta.1` release is coordinated:

1. Control plane ships a dual-wire code path accepting both `v1.2` and
   `v1.3` wire formats, gated by a request capability header.
2. Spize Desktop does the same, picking the wire version per recipient
   from the `/v1/capabilities` endpoint.
3. SDKs ship `v1.3` only; SDK users reinstall on release day.
4. The `v1.2` compatibility path is removed 30 days after the tag
   push. CHANGELOG calls out the sunset date prominently.

## Consequences

- Users get 30 days to upgrade their side of the integration.
- Control plane carries temporary dual-parsing complexity; deleted on
  the sunset date.
- The desktop must ship before the SDK sunset so users have a path
  that still works.
- Post-30-day, anyone on v1.2 bytes gets a 426 Upgrade Required with
  a documentation pointer.
