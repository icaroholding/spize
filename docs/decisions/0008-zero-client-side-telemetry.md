# ADR-0008: Zero client-side telemetry, forever

## Status

Accepted 2026-04-21.

## Context

AEX is a file-transfer protocol for agents that, on certain tiers, moves
sensitive documents between organizations. Any SDK-side phone-home —
"which agents are registered", "which endpoints are called", "error
frequencies" — is a privacy liability the protocol's value proposition
cannot carry. Even opt-in telemetry complicates the sales pitch for the
enterprise tier.

## Decision

AEX SDKs (Rust, Python, TypeScript, future Go / Java) will never ship
telemetry — no anonymized pings, no error beacons, no usage counts. The
only observation the SDK emits is `AEX_NETWORK_STATE` and related
advisory stdout lines on the data-plane binary, which are consumed
locally by the user's own orchestrator.

## Consequences

- Server-side analytics are limited to operations the user explicitly
  initiates against the hosted control plane.
- Product decisions around SDK adoption must rely on GitHub install
  metrics, crates.io / npm / PyPI download counts, and direct user
  outreach — not on SDK-generated datasets.
- This is a credibility moat against competitors that include telemetry
  by default. We advertise it in the README.
