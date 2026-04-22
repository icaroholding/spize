# Runbook: generic `401 Unauthorized`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** anything not covered by the specific runbooks —
  [signature-invalid](signature-invalid.md),
  [agent-not-registered-or-revoked](agent-not-registered-or-revoked.md),
  [wrong-recipient](wrong-recipient.md).

## Likely cause

A CP authorisation check failed that isn't yet classified into its
own runbook.

## Remediation

Read `message` — it names the specific failure. Common examples:

- `unknown sender` — the sender's `agent_id` isn't registered on this
  CP.
- `recipient agent not registered` — same, recipient side.
- `recipient signature does not verify` — the request was signed with
  a key that doesn't match the stored recipient pubkey.

If the remediation is non-obvious, file a PR adding a runbook page
and extending the mapping in
`crates/aex-control-plane/src/error.rs::runbook`.

## Related

- All handlers under `crates/aex-control-plane/src/routes/`
