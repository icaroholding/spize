# Runbook: `signature does not match challenge`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** typically `signature does not match challenge` or
  `signature does not verify against any active key`

## Likely cause

1. **Wrong key signed the message.** The SDK reconstructed the canonical
   bytes with one key but submitted the pubkey from a different one.
   Happens after a botched rotation when the caller forgot to swap out
   their persisted identity file.
2. **Clock skew.** The `issued_at` on the wire doesn't match what the
   caller used when constructing the canonical bytes. See also
   [clock-skew](clock-skew.md) — the freshness check usually catches
   this first, but a client with a wildly wrong clock can slip through.
3. **Canonical-bytes drift.** The signed bytes don't match what the
   server re-derives. Most commonly: a non-ASCII character in `org` /
   `name` / `filename` snuck past the client-side validator.
4. **Tampered payload.** A middlebox rewrote part of the request.
   Rare but possible behind proxies that "sanitise" JSON.

## Remediation

```bash
# 1. Confirm the identity file matches the key the CP has on record.
aex-cli agent show <agent_id>   # (planned — see TODO-7 in plan)
# Until the CLI ships: GET /v1/agents/<agent_id> and compare
# public_key_hex to your local identity's public half.

# 2. If they don't match, either:
#    (a) you have the wrong identity file — restore from backup, or
#    (b) the CP's pubkey is stale — trigger a rotation:
#        SpizeClient(...).rotate_key(new_identity)
```

If rotation is the cause, remember the grace window: signatures from
the old key keep working for 24h post-rotation (ADR-0024). If you're
outside that window you'll get this error on any request signed by
the old key — regenerate a signature with the current identity.

## Related

- [ADR-0024 — formal key rotation](../decisions/0024-formal-key-rotation-v1-3.md)
- `crates/aex-control-plane/src/verify.rs` — signature verification path
- `crates/aex-core/src/wire.rs` — canonical bytes helpers
