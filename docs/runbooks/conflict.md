# Runbook: generic `409 Conflict`

## Symptom

- **Status:** `409 Conflict`
- **`code`:** `conflict`
- **Message:** varies — anything the CP returns as 409 that isn't
  covered by the more specific runbooks
  ([nonce-replay](nonce-replay.md),
  [agent-already-exists](agent-already-exists.md),
  [rotation-race](rotation-race.md)).

## Likely cause

A state-transition guard on the CP refused the operation. Typical:

- Trying to `ack` a transfer that's already `delivered`.
- Trying to `download` a transfer that's in `rejected` state.
- Any unique constraint the mapping function hasn't learned to
  classify yet.

## Remediation

Read the `message` field — the CP names the exact guard. If you're
seeing this for a generic case and think it deserves its own page,
open a PR adding one and extending
`error::runbook::runbook_url` to route the relevant keywords.

## Related

- `error::ApiError::Conflict` variants across
  `crates/aex-control-plane/src/routes/`
