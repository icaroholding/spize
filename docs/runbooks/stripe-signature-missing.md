# Runbook: `stripe_signature_missing`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `stripe_signature_missing`
- **Message:** `Stripe-Signature header is missing.`

## Likely cause

Somebody (or something) POSTed to `/webhooks/stripe` without
including the `Stripe-Signature` header. Stripe's own requests
always include it, so a missing header means:

1. **A manual / exploratory curl** against the endpoint without
   the signing machinery. Expected — 401 is the correct response.
2. **A misconfigured proxy** (Cloudflare, nginx) stripping the
   header before forwarding to the Fly app. Check the proxy logs.
3. **A legitimate tester using `stripe listen`** without the
   `--forward-to` option — `stripe trigger ...` alone does not
   call your server; you need `stripe listen --forward-to
   https://api.spize.io/webhooks/stripe`.

## Remediation

For case 1 (manual test): nothing to do — the 401 is what the
handler should return.

For case 2: inspect proxy config — Stripe uses a header name the
proxy might accidentally be lowercase-normalising then dropping.
HTTP header names are case-insensitive; make sure the proxy isn't
using a case-sensitive allowlist.

For case 3: use Stripe CLI properly:

```bash
stripe login
stripe listen --forward-to https://api.spize.io/webhooks/stripe
# in another terminal:
stripe trigger customer.subscription.created
```

The CLI re-signs the triggered event with your test-mode secret
before forwarding, so the header is present end-to-end.

## Related

- `crates/aex-control-plane/src/routes/webhooks/stripe.rs`
