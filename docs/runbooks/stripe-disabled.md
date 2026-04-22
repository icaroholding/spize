# Runbook: `stripe_disabled`

## Symptom

- **Status:** `503 Service Unavailable`
- **`code`:** `stripe_disabled`
- **Message:** `Stripe webhook not configured; set STRIPE_WEBHOOK_SECRET + STRIPE_PRICE_DEV + STRIPE_PRICE_TEAM and restart.`

## Likely cause

The control plane started without one or more Stripe environment
variables. The webhook handler refuses to accept events when it
can't verify them — a 503 is better than silently dropping a paying
customer's subscription state.

## Remediation

1. Verify the Fly app has all three secrets:

    ```bash
    fly secrets list -a aex-control-plane | grep -i stripe
    ```

    You should see:
    - `STRIPE_WEBHOOK_SECRET`
    - `STRIPE_PRICE_DEV`
    - `STRIPE_PRICE_TEAM`

2. Missing ones: set them and the restart is automatic.

    ```bash
    fly secrets set \
        STRIPE_WEBHOOK_SECRET=whsec_... \
        STRIPE_PRICE_DEV=price_1... \
        STRIPE_PRICE_TEAM=price_1... \
        -a aex-control-plane
    ```

3. Confirm via:

    ```bash
    curl -s https://api.spize.io/healthz   # must return 200
    ```

    And try a test webhook from the Stripe dashboard
    (Developers → Webhooks → your endpoint → Send test event).

## Related

- `crates/aex-control-plane/src/routes/webhooks/stripe.rs`
- `crates/aex-control-plane/src/config.rs::StripeConfig`
