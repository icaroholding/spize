# ADR-0026: JWS-signed `did:web` document with AEX extension proof block

## Status

Accepted 2026-04-21.

## Context

`did:web` is the most-deployed DID method and the simplest way to tie a
domain the user controls to a cryptographic identity. Its stock document
is not self-signed; any admin with write access to `/.well-known/` can
substitute one. For AEX identities claimed via `did:web`, we need a
proof block that binds the document to the Ed25519 key the AEX protocol
already verifies.

## Decision

When an agent claims `did:web` binding in its registration, the
corresponding `/.well-known/did.json` document carries an AEX extension
`proof` block — a detached JWS signed with the agent's Ed25519 signing
key. The control plane verifies the proof at registration and on
periodic re-checks (weekly). A document without a valid proof block is
treated as an unsigned identity claim and refused.

## Consequences

- `did:web`-backed AEX identities are cryptographically verifiable end
  to end, without trusting DNS or HTTPS alone.
- Lost control of the domain is recoverable: present a new proof block
  signed by a stored key.
- An AEX-aware `did:web` resolver can surface the proof to other
  ecosystems that want DID-verified identity.
- Re-signing cadence (weekly) is documented in the SECURITY runbook.
