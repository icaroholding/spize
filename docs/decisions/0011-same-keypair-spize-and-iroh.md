# ADR-0011: Same Ed25519 keypair backs `spize:*` identity and Iroh NodeID

## Status

Accepted 2026-04-21.

## Context

Sprint 2 introduces Iroh as a peer-to-peer transport (ADR-0002). Iroh
identifies nodes by `NodeID` — a 32-byte Ed25519 public key, exactly the
shape of an AEX identity's signing key. Maintaining two separate keypairs
doubles the user's secret-management surface, doubles rotation pain, and
creates an opportunity for a subtle identity split (signed-as-A, connected-
as-B) that attackers could exploit.

## Decision

The Ed25519 keypair that produces a `spize:org/name:fingerprint` identity
is the same keypair used as the Iroh `NodeID` for that node. `AgentId` and
`NodeID` are two encoded views of the same 32 bytes.

## Consequences

- One keypair to protect, one rotation event (ADR-0024).
- A recipient verifying a peer's Iroh connection can verify it against the
  same fingerprint they use for wire-format signature checks.
- Key-exfiltration blast radius covers both transport and protocol layers —
  an acceptable simplification given the rotation protocol.
- Identity file format (future) must carry a single Ed25519 secret usable
  for both purposes.
