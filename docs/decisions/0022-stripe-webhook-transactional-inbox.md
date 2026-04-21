# ADR-0022: Stripe webhook — transactional inbox + idempotency key

## Status

Accepted 2026-04-21.

## Context

Stripe delivers webhook events at-least-once. Processing the same
`checkout.session.completed` twice can double-issue an API key, inflate
usage counters, or corrupt a subscription's grandfather-pricing flag
(ADR-0007). The canonical fix is to deduplicate on Stripe's event ID
inside the same DB transaction that persists the business side effect.

## Decision

The Stripe webhook handler uses the transactional inbox pattern:

1. Upsert the event ID into a `stripe_webhook_events` table with a
   unique constraint on `event_id`.
2. If the upsert sees a conflict (event already processed), return 200
   immediately without re-applying the side effect.
3. Otherwise, apply the side effect + insert the inbox row inside a
   single Postgres transaction.

## Consequences

- Duplicate deliveries are inert by construction; no compensating
  logic needed.
- The inbox table grows with webhook volume; a maintenance job prunes
  rows older than 90 days (Stripe's retention window).
- Processing latency adds one DB INSERT per webhook; negligible.
- Failure modes collapse into one: if the transaction rolls back, the
  event is retried by Stripe on its own schedule.
