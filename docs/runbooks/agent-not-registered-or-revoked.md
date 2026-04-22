# Runbook: `no active key for agent`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** `no active key for agent (unregistered or revoked)`

## Likely cause

1. **Caller never registered.** The CP has no `agents` row for the
   canonical `agent_id`; every signed action fails up-front.
2. **Agent was revoked.** All key rows have a finite `valid_to` that's
   already in the past — no current key, no grace-window key.
3. **Agent registered on a different control plane.** E.g. staging
   vs production. The `agent_id` the caller is using exists somewhere,
   just not on the CP they're talking to.

## Remediation

Register the caller first:

```python
SpizeClient(base_url, identity).register()
```

Registration is idempotent at the "agent_id + pubkey" level: calling
it twice with the same identity returns 409 (see
[agent-already-exists](agent-already-exists.md)) but the second call
is safe.

If the call site has been registering successfully elsewhere but
fails here, you're pointing at the wrong control plane URL.
Double-check `AEX_CONTROL_PLANE_URL` or the `base_url` constructor
argument.

## Related

- `crates/aex-control-plane/src/verify.rs::verify_with_valid_keys` —
  this is the error emitter
- [ADR-0024 — formal key rotation](../decisions/0024-formal-key-rotation-v1-3.md)
  — defines "active key" and the grace window
