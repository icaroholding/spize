# ADR-0024: Formal `spize-rotate-key:v1` protocol in `v1.3.0-beta.1`; 24 h grace

## Status

Accepted 2026-04-21.

## Context

Ed25519 keys don't expire, but they get compromised, lost, and rotated
for policy reasons. Today AEX has no story for rotation: re-registering
an agent with a new key reuses the `spize:org/name:fingerprint` only if
the fingerprint changes, which is exactly the problem. A formal rotation
message ties old and new keys to the same agent identity without a
break in the signature chain.

## Decision

`v1.3.0-beta.1` introduces a new canonical wire message
`spize-rotate-key:v1` signed by the outgoing key and carrying the new
public key. The control plane accepts both keys for **24 h** after the
rotation is recorded; after that window only the new key is valid.
Rotation events are logged in the audit chain.

## Consequences

- A compromised key has a hard deadline for remediation (24 h grace).
- Agent identity is decoupled from any single keypair — the `spize:*`
  ID survives rotation.
- Recipients verifying old signatures during the grace window must
  consult the control plane's `GET /v1/agents/:id/key-history`.
- Rotation is a deliberate operation, not an automatic one; no
  scheduled auto-rotation in v1.x.
