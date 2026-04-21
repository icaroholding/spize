# ADR-0025: JWS-signed `/.well-known/agent-card.json`

## Status

Accepted 2026-04-21.

## Context

The A2A spec (and several agent frameworks) expect an agent to publish a
capability document at `/.well-known/agent-card.json`. That document is
consumed as authoritative by third parties; without a signature, any
intermediary could tamper with declared capabilities, endpoints, or
identity claims. Signing it as a JWS using the agent's Ed25519 key makes
the document verifiable and tamper-evident.

## Decision

Each agent's `/.well-known/agent-card.json` is a JWS (JSON Web
Signature) over the agent card payload, signed with the agent's current
Ed25519 signing key (ADR-0011). The JWS header includes the agent's
fingerprint; verifiers resolve the key through the AEX control plane
(or DID document, ADR-0026). Unsigned agent cards are rejected.

## Consequences

- A2A interop works without sacrificing identity strength.
- Adding a capability bit is a new card signing event, not a protocol
  bump.
- Key rotation (ADR-0024) invalidates the old card at the 24 h
  deadline; agents must re-sign.
- The card format is pinned in the spec; agents with non-JWS cards
  are rejected by conformant clients.
