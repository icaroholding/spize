# Runbook: `stripe_signature_invalid`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `stripe_signature_invalid`
- **Message:** `no v1 signature matched expected HMAC` or `timestamp skew
  outside 300s tolerance` (the wire doesn't echo the specific reason
  — check the server log for the exact `reason=…` field).

## Likely cause

1. **Signing secret mismatch.** The `STRIPE_WEBHOOK_SECRET` env
   var on the server is not the `whsec_…` Stripe dashboard shows
   for this endpoint. Happens when:
   - You rotated the secret in Stripe without updating Fly.
   - You copied the test-mode secret into a live-mode endpoint
     (or vice-versa — test and live have DIFFERENT secrets).
   - You configured multiple webhook endpoints and mixed up which
     `whsec_…` belongs to which.

2. **Body mutation in transit.** Something between Stripe and the
   server changed a byte of the body (JSON reformatting proxy,
   utf-8 re-encoding). HMAC is byte-sensitive; any change breaks
   the signature. Check Cloudflare rules, any "response
   optimizer" middleware.

3. **Clock skew.** The Fly machine clock drifted more than 300s
   from real time. Rare but possible on VM restart. `fly logs`
   should show the `reason = "timestamp skew outside 300s …"`
   line if this is the cause.

4. **Replay attempt.** An attacker captured an old webhook body
   and is replaying it now. The 300s tolerance kills these by
   default; if you're seeing this message repeatedly with the
   same `t=` from server logs, investigate network traffic.

## Remediation

For case 1:

```bash
# In Stripe dashboard: Developers → Webhooks → your endpoint
# → Signing secret → "Reveal" → copy whsec_…
fly secrets set STRIPE_WEBHOOK_SECRET=whsec_... -a aex-control-plane
```

For case 2: inspect any middleware that buffers or touches request
bodies. Raw pass-through is required.

For case 3: `fly ssh console -a aex-control-plane` then `date -u`
— compare to `date -u` on your laptop. If off by >5s, file a Fly
support ticket.

## Related

- `crates/aex-control-plane/src/routes/webhooks/stripe.rs::verify_signature`
- Stripe docs: https://stripe.com/docs/webhooks/signatures
