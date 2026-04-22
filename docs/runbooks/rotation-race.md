# Runbook: `agent key rotated concurrently`

## Symptom

- **Status:** `409 Conflict` (or `401 Unauthorized`, depending on race
  interleaving)
- **`code`:** `conflict` / `unauthorized`
- **Message:** `agent key rotated concurrently; retry with the new
  current key` or
  `rotation conflict (active_key_race): another rotation to this key
  already exists`

## Likely cause

Two `POST /v1/agents/rotate-key` calls landed simultaneously for the
same agent. ADR-0024 guarantees exactly one wins; the loser gets
this error. The invariant is enforced by (a) a conditional UPDATE
filtering on the pre-rotation `public_key_hex` and (b) a partial
unique index `(agent_id) WHERE valid_to IS NULL`. Either way the
loser's `insert_rotation` call sees zero rows updated and aborts.

## Remediation

Refresh the current key and retry:

```python
# Before:
client = SpizeClient(base_url, old_identity)
try:
    client.rotate_key(new_identity)
except SpizeHTTPError as e:
    if e.status_code == 409 and "rotated concurrently" in (e.message or ""):
        # Pull the CP's current opinion
        agent = client.get_agent(old_identity.agent_id)
        current_pub = agent["public_key_hex"]
        if current_pub == new_identity.public_key_hex:
            # Someone else did the rotation we wanted — we're done.
            return
        # Some third party took the active slot. Load that key's
        # identity from wherever you keep it and rotate from there.
        raise
```

If this fires unexpectedly in a single-caller deployment, two
instances are running with the same identity file. Investigate the
double-deployment — it also means both instances think they own the
same secret, which is usually not what you want.

## Related

- [ADR-0024 — formal key rotation](../decisions/0024-formal-key-rotation-v1-3.md)
- `crates/aex-control-plane/src/db/agent_keys.rs::insert_rotation`
- Integration test `concurrent_rotate_key_race` in
  `crates/aex-control-plane/tests/agents_rotate_key.rs`
