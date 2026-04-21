# ADR-0032: Dedicated Fly.io testbed + `cargo-fuzz` + golden vector JSON

## Status

Accepted 2026-04-21.

## Context

To run meaningful chaos tests (ADR-0031) we need a reproducible
environment independent of the developer laptop. Fly.io is already the
hosting platform (ADR-0003); a sibling app `aex-testbed` gives us a
place to run end-to-end suites against a realistic topology. Separately,
`cargo-fuzz` catches wire-format parser corruption that neither unit
nor integration tests reach. Golden vectors (canonical bytes for every
wire message in a JSON file) pin the wire format across SDKs.

## Decision

We run three test artefacts alongside the main CI:

1. `aex-testbed` on Fly.io (single AMS region, toxiproxy between peers).
2. `cargo-fuzz` targets for `aex-core` wire parsers and
   `aex-identity` signature verifiers, scheduled nightly.
3. `tests/golden/wire-v1.json` — a committed file of
   `{canonical_bytes: hex, expected_signature: hex}` tuples each SDK
   must reproduce.

## Consequences

- Testbed costs ~$5/month Fly.io; funded by ADR-0010 budget.
- Fuzz findings get triaged on a weekly cadence (ADR-0037 contributor
  onramp).
- Golden vectors regenerate only when the wire format intentionally
  changes (v1.3.0-beta.1 event, then frozen per ADR-0018).
- New SDKs (Go, Java) prove correctness by reproducing the golden
  vectors before shipping.
