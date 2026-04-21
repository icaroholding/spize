# ADR-0031: Layered testing — property (proptest) + scenario (mocks) + chaos (toxiproxy)

## Status

Accepted 2026-04-21.

## Context

A protocol this fundamental needs more than unit tests. Property-based
tests catch cases the author didn't think of. Scenario tests with
mocks reproduce specific failure modes. Chaos tests against a real-ish
environment surface emergent behaviour under network degradation. Each
layer covers a class of bug the others miss; doing only one is false
economy.

## Decision

Each crate that warrants it uses three test layers:

1. **Property** — `proptest` on pure functions (retry curves, wire
   parsers, state machine transitions).
2. **Scenario** — unit tests with mocks (axum test servers for HTTP,
   `sqlx::test` for DB, custom transports for network).
3. **Chaos** — integration tests against a Fly.io testbed
   (ADR-0032) with toxiproxy between the peers.

Property + scenario run on every PR; chaos runs nightly.

## Consequences

- Test runtime budget is significant: PR CI ~5 min, nightly chaos ~45
  min.
- Property tests surface footguns early (jitter-bounds regression,
  state-machine invariants).
- Chaos tests give us confidence in the protocol under real network
  stress, not idealised conditions.
- New crates inherit the same layering expectation.
