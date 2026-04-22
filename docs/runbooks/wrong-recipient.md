# Runbook: `you are not the recipient`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** `you are not the recipient` or
  `recipient does not match transfer`

## Likely cause

1. **Wrong identity on the calling SpizeClient.** A recipient-facing
   action (`download`, `ack`, `request_ticket`) is being signed with
   a different agent's identity than the transfer's stored `recipient`.
2. **Identity confused in a multi-tenant process.** A shared
   `SpizeClient` pool mixed identities between tasks.

## Remediation

Ensure the `SpizeClient` instance used for recipient actions was
constructed with the same `Identity` as the transfer's `recipient`
field. Clients are cheap to build; in multi-tenant code create a
per-caller client rather than sharing.

## Related

- `verify_recipient_receipt` in
  `crates/aex-control-plane/src/routes/transfers.rs`
- SDK `SpizeClient.identity.agent_id` / `.agentId`
