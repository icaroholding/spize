# Runbook: `internal server error`

## Symptom

- **Status:** `500 Internal Server Error`
- **`code`:** `internal_error`
- **Message:** `internal server error` (the real cause is NEVER
  surfaced on the wire — check server logs)

## Likely cause

Any unexpected failure inside the CP: DB driver error, serde panic,
downstream service timeout, unwrap on a `Result` that wasn't
supposed to fail. The `ApiError::Internal` variant explicitly masks
the cause on the wire so operators don't leak stack shapes to
external callers.

## Remediation

This one is NOT actionable from the caller side.

**Operator steps:**

1. Correlate the 500 with the CP logs:
   ```bash
   # Look for the exact request at the reported timestamp.
   # ApiError::Internal::into_response emits a
   # tracing::error!() with the source error chain.
   kubectl logs aex-control-plane-<pod> --since=5m | grep -E "ERROR .* internal error"
   ```
2. Inspect the `error` field for the real root cause — DB error,
   JSON deserialise failure, downstream signer error, etc.
3. File a ticket against the CP with the correlation id +
   server-side error message so the handler can catch the case and
   map it to a better (4xx) error if it's actually client-fixable.

**Caller workarounds:**

- Retry with exponential backoff: internal errors are frequently
  transient (DB connection blip, restart race).
- Don't parse the `message` for remediation logic — this field is
  deliberately opaque.

## Related

- `ApiError::Internal` in `crates/aex-control-plane/src/error.rs`
- `ApiError::into_response` — where the 500 + masked message is
  constructed
