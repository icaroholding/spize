# Runbook: `stripe_processing_failed`

## Symptom

- **Status:** `500 Internal Server Error`
- **`code`:** `stripe_processing_failed`
- **Message:** `internal error processing event; stripe will retry`

## Likely cause

The signature verified and the event parsed, but something blew up
while updating the database. Possible causes:

1. **Migrations not applied.** Fresh deploy where `stripe_events`
   or `subscriptions` tables don't exist yet. The server's own
   startup should apply migrations automatically — if you're
   seeing this on boot, migration likely failed.
2. **DB connection exhausted.** Pool saturated, `acquire_timeout`
   tripped. Look at connection-pool metrics.
3. **DB unavailable.** Postgres down, flycast routing broken.
4. **Constraint violation.** A subscription event arrived with a
   `stripe_subscription_id` that conflicts with a different
   customer's existing row — would indicate Stripe data corruption
   or a subscription being transferred (rare).

## Remediation

1. Check server logs for the underlying error:

    ```bash
    fly logs -a aex-control-plane | grep -i "error processing stripe"
    ```

    The log line carries `event_id`, `event_type`, and the `error`
    field which tells you exactly what sqlx saw.

2. If it's a migration issue:

    ```bash
    fly ssh console -a aex-control-plane
    # in the console:
    cd /app && ./aex-control-plane --migrate-only   # (if we ship the flag)
    # or restart the machine so startup re-runs migrations
    fly machine restart -a aex-control-plane <machine_id>
    ```

3. If it's a DB unreachable issue, check Postgres:

    ```bash
    fly pg connect -a aex-postgres
    ```

4. **Stripe will retry automatically** up to 3 days. No manual
   replay is usually needed — once the underlying cause is fixed,
   the next retry will succeed and the event is processed
   idempotently.

## Related

- `crates/aex-control-plane/src/routes/webhooks/stripe.rs::process_event`
- `crates/aex-control-plane/migrations/20260423000003_stripe_events.sql`
- `crates/aex-control-plane/migrations/20260423000004_subscriptions.sql`
