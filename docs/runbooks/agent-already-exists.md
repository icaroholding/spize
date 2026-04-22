# Runbook: `public_key already registered` / `agent_id already registered`

## Symptom

- **Status:** `409 Conflict`
- **`code`:** `conflict`
- **Message:** `public_key already registered` or
  `agent_id already registered`

## Likely cause

1. **Repeat registration.** The caller generated an identity, persisted
   it, and is calling `register()` again on startup without checking.
   Safe to ignore — the `agents` row already exists.
2. **Pubkey collision at a different `org/name`.** Two organisations
   tried to register the same Ed25519 pubkey under different names.
   Astronomically unlikely by accident; if it happens, someone has
   access to the other identity's secret bytes.
3. **org/name collision with a different pubkey.** Same `org/name`
   already registered with someone else's pubkey. A key lost + re-minted
   hits this; you need `rotate-key` (ADR-0024), not a fresh register.

## Remediation

- **Benign repeat register:** catch the 409 and move on. The first
  registration succeeded; you're already in the CP.
- **Pubkey collision:** treat it as a security incident — rotate the
  affected identity to a freshly-generated keypair and investigate
  how the secret leaked.
- **Name collision, want to recover:** use
  `SpizeClient.rotate_key(new_identity)` with the OLD identity
  signing the rotation. If you lost the old secret, you can't
  recover the `spize:org/name:fingerprint` — pick a new name.

## Related

- `crates/aex-control-plane/src/db/agents.rs::unique_violation_field`
  — classifies which constraint fired
- `POST /v1/agents/rotate-key` handler in
  `crates/aex-control-plane/src/routes/agents.rs`
