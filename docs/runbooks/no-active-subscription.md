# Runbook: no active customer subscription

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** `no active customer subscription` or
  `no active customer subscription (status: <stripe-status>)`

## Likely cause

The session cookie validated (the caller is who they claim to be)
but their `subscriptions.status` is not in the set
`{active, trialing}`. Common values that hit this branch:

- `canceled` — the subscription was deleted on Stripe (manual
  ops, customer cancel via portal). Webhook revoked their api_keys
  too; new mints are blocked.
- `past_due` — payment failed. Stripe is retrying the card. Once
  the card succeeds, subscription flips back to `active` and
  mints unlock.
- `unpaid` — Stripe gave up retrying. Customer must update card.
- `incomplete` — initial payment hasn't cleared yet (rare race
  during checkout). Usually resolves within seconds.

## Remediation

For the customer: dashboard should show a banner pointing at the
Stripe Customer Portal — they update their card / re-subscribe
there, the webhook fires, status flips back to active, the next
mint succeeds.

For ops: confirm via the admin endpoint that the subscription
exists at all:

```bash
curl -s https://api.spize.io/v1/admin/api-keys \
    -H "Authorization: Bearer $AEX_ADMIN_TOKEN" \
    | jq '.keys | map(select(.customer_id == "cus_…"))'
```

If no row: the customer never paid (or webhook never landed —
check `stripe_events` table). If row exists with `revoked_at`
populated: they were canceled and need to re-subscribe.

## Related

- `crates/aex-control-plane/src/routes/customer/api_keys.rs::fetch_active_subscription`
- `docs/runbooks/stripe-processing-failed.md` (if webhooks aren't
  syncing at all)
