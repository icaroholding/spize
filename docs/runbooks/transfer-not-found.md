# Runbook: `transfer not found`

## Symptom

- **Status:** `404 Not Found`
- **`code`:** `not_found`
- **Message:** `transfer <transfer_id> not found` or
  `unknown transfer: <transfer_id>`

## Likely cause

1. **Typo or expired transfer_id.** Transfers are capability-bearer
   identifiers; losing the id loses the reference. There's no listing
   endpoint that recovers them.
2. **Different CP.** Same story as agents.
3. **Transfer was admin-pruned.** Not a supported operation today
   but planned; an operator could have removed the row.

## Remediation

Use the caller's `inbox()` to find pending transfers for the
recipient. For senders that already lost the id, the transfer can't
be recovered — resend.

## Related

- `GET /v1/transfers/:transfer_id` handler in
  `crates/aex-control-plane/src/routes/transfers.rs`
- `POST /v1/inbox` for recipient-side discovery
