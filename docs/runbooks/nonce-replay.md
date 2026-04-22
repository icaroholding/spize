# Runbook: `nonce already used`

## Symptom

- **Status:** `409 Conflict`
- **`code`:** `conflict`
- **Message:** `nonce already used` or `intent nonce already used`

## Likely cause

1. **Retry with a stale nonce.** The caller resent a previously-sent
   request verbatim. Every signed payload (register, rotate-key,
   transfer intent, receipt) carries a nonce that the CP consumes
   once; replaying it is exactly what the check exists to block.
2. **Clock drift past the freshness window, then retry.** The first
   attempt got rejected on `issued_at` skew, the caller bumped `ts`
   without regenerating `nonce`. Rare but has happened.
3. **Parallel duplicate submission.** Two workers picked up the same
   queue job and both fired the request. One wins; the other sees
   this error.

## Remediation

Regenerate the nonce and retry. SDKs do this automatically via
`random_nonce()` on every call; client code that builds the payload
manually must not cache nonces.

```python
# Wrong — reuses the same nonce on retry
payload["nonce"] = "<captured value>"
retry_send(payload)

# Right — every attempt builds fresh canonical bytes from scratch
for attempt in range(3):
    try:
        client.send(recipient=..., data=...)
        break
    except SpizeHTTPError as e:
        if e.status_code in {502, 503, 504}:
            continue
        raise
```

If you're hitting this error on a request the client built fresh, the
real cause is upstream — inspect request logs to confirm the duplicate
didn't come from your own retry loop or a sidecar proxy.

## Related

- `crates/aex-control-plane/src/db/agents.rs::consume_nonce` —
  registration nonces
- `crates/aex-control-plane/src/db/transfers.rs::consume_intent_nonce` —
  transfer nonces
- `crates/aex-control-plane/src/db/agent_keys.rs::consume_rotate_nonce` —
  rotate-key nonces
