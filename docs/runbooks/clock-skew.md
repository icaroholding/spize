# Runbook: `issued_at is outside allowed skew`

## Symptom

- **Status:** `400 Bad Request`
- **`code`:** `bad_request`
- **Message:** `issued_at is outside allowed skew (±300s)` or similar

## Likely cause

1. **Caller's clock is wrong.** Containers with no NTP, VMs paused
   then resumed, or dev boxes that drifted. `issued_at` is Unix
   seconds on the caller's clock; the CP rejects anything more than
   300 s away from its own clock.
2. **`issued_at` not regenerated on retry.** A retry path reused the
   value from the first attempt, which has now aged past the skew.
3. **Wrong timezone handling.** The SDK helpers all use `unix_timestamp()`
   so this shouldn't happen for code that sticks to `random_nonce()`
   + `time.time()` / `Date.now()/1000`. Custom payload builders that
   use a local-timezone epoch can trip this.

## Remediation

```bash
# Verify caller clock
date -u +%s
curl -s http://<control-plane>/healthz | jq -r '.now_unix // empty'
# If the two differ by more than ~60s, fix the caller's NTP.
```

In Docker:

```dockerfile
# Add an NTP sync step to your image
RUN apt-get update && apt-get install -y --no-install-recommends ntpdate
```

On fly.io / k8s, make sure the node's kernel clock is trustworthy
— the sandbox inherits it.

For caller code, always compute `issued_at` fresh per attempt:

```python
issued_at = int(time.time())    # Right — evaluated per call
```

```typescript
const issuedAt = Math.floor(Date.now() / 1000);  // Right
```

## Related

- `MAX_CLOCK_SKEW_SECS` in `crates/aex-core/src/wire.rs`
- `is_within_clock_skew` — overflow-safe freshness check
