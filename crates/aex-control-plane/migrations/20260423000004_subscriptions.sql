-- Sprint 4 (revenue): customer subscription state, synced from
-- Stripe webhook events.
--
-- This table is the **source of truth for "can this customer
-- generate API keys?"**. The customer dashboard (PR #43+) reads it
-- on every mint call to check the paying relationship is still
-- valid; only a row with `status = 'active'` authorizes the mint,
-- and the `tier` here decides what the new api_key.tier will be.
--
-- We deliberately do NOT mint api_keys automatically on webhook
-- receipt — the plaintext must be handed to the customer exactly
-- once (by the dashboard UI, after login). Storing plaintext in
-- the DB while waiting for an email round-trip is a security
-- regression we refuse to take; the industry pattern (Stripe,
-- OpenAI, AWS, Anthropic) is "pay → dashboard → self-mint", and
-- that's what this table enables.

CREATE TABLE subscriptions (
    -- Stripe's customer.id (e.g. "cus_Q…"). One active row per
    -- customer. If a customer later holds multiple subscriptions
    -- (e.g. add-on products), this PK is promoted to a FK and
    -- `stripe_subscription_id` becomes the PK.
    stripe_customer_id      TEXT            PRIMARY KEY,

    -- Stripe's subscription.id (sub_…). Unique per customer today
    -- (1:1) — the UNIQUE constraint enforces that invariant.
    stripe_subscription_id  TEXT            NOT NULL UNIQUE,

    -- Plan the customer is on. Derived at webhook time by looking
    -- up `data.object.items.data[0].price.id` against the
    -- `STRIPE_PRICE_DEV` / `STRIPE_PRICE_TEAM` env vars.
    -- Free text at the DB layer for the same reason as
    -- `api_keys.tier` — no schema migration per new tier.
    tier                    TEXT            NOT NULL,

    -- Stripe subscription.status, copied verbatim. Common values:
    -- active, past_due, canceled, trialing, incomplete,
    -- incomplete_expired, unpaid. Only `active` and `trialing`
    -- authorize api_key mint; the others either wait (past_due,
    -- incomplete) or deny (canceled, unpaid).
    status                  TEXT            NOT NULL,

    created_at              TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Query shape: "all active subscriptions", "churn by status bucket".
CREATE INDEX idx_subscriptions_status ON subscriptions (status);
