# Runbook: `stripe_event_malformed`

## Symptom

- **Status:** `400 Bad Request`
- **`code`:** `stripe_event_malformed`
- **Message:** `cannot parse event JSON: <parse error>`

## Likely cause

The signature verified (the caller has the shared secret), but the
body doesn't parse as a Stripe event envelope with `id` + `type` +
`data.object` fields. Possible causes:

1. **A custom test payload** you built locally with `stripe trigger
   --override` and broke the shape by mistake. Rare in prod.
2. **A Stripe API version change** that altered the event envelope.
   Stripe is normally strict about backwards compat; this would be
   a rolling announcement, not a surprise. Check
   https://stripe.com/docs/api/versioning if you suspect this.
3. **Body mutation in transit** that still happens to pass the
   signature check (improbable given HMAC is byte-sensitive, but
   not impossible with a buggy middleware that mutates bytes AND
   re-signs).

## Remediation

1. Check the Stripe dashboard → Developers → Webhooks → Recent
   attempts → click the failed attempt. The "Event" tab shows what
   Stripe sent. If it's a real Stripe event with the standard
   shape, something mutated it in transit — suspect middleware.
2. If the attempt is a manual/test one you triggered, fix the
   payload to include `id`, `type`, and `data.object`.

## Related

- `crates/aex-control-plane/src/routes/webhooks/stripe.rs::StripeEvent`
