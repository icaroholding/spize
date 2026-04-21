# ADR-0029: Normative spec (`docs/protocol-v1.md` §5) + per-language conformance suite + CI gate

## Status

Accepted 2026-04-21.

## Context

Three language SDKs (Rust, Python, TypeScript) implement retry behaviour
and captive-portal detection. Without a normative spec + conformance
tests, the three implementations inevitably drift — the Python SDK
picks ±200 ms jitter because it felt nicer, the TypeScript SDK caps
attempts at 5, the Rust side-eye stares at both. The fix is one spec,
one set of pinned values, and a test in each language that fails if
the values move.

## Decision

`docs/protocol-v1.md` §5 is normative. Each SDK ships a conformance
test that pins the §5 values (retry parameters, captive-portal probe
URLs, state strings). The Rust conformance lives at
`crates/aex-net/tests/conformance/`. CI runs all three SDK test suites
on every PR; a drift fails the build.

## Consequences

- Changing any §5 number requires coordinated edits in three SDKs +
  the spec — a deliberate event, not a casual patch.
- New SDKs (Go Phase 4, Java Phase 5) must land a conformance test as
  a release prerequisite.
- Spec bugs that escape get caught when the first SDK adds a test the
  others weren't pinned to.
