-- Sprint 4 PR 7: customer email registry.
--
-- The Stripe webhook syncs each Stripe Customer into this table by
-- listening to `customer.created` and `customer.updated` events.
-- The `subscriptions` table holds the *paying* relationship; this
-- one holds the *identity* relationship (email → stripe_customer_id).
--
-- The customer dashboard's magic-link login resolves an email to a
-- stripe_customer_id via this table. From there `subscriptions`
-- tells us if the customer is active and what tier they get when
-- they mint API keys.

CREATE TABLE customers (
    -- Stripe's customer.id (e.g. "cus_Q…"). Authoritative identity
    -- across our entire revenue surface.
    stripe_customer_id   TEXT            PRIMARY KEY,

    -- Email address Stripe has on file. Lower-cased on insert via
    -- the application layer (Postgres CITEXT would also work but
    -- adds an extension dependency we don't need yet).
    -- UNIQUE so the magic-link flow's "find customer by email" is
    -- a deterministic lookup. If the same person has TWO Stripe
    -- customers with the same email (rare, possible after manual
    -- ops cleanup), the second `customer.created` will conflict
    -- and the webhook handler logs + skips — safer than picking
    -- one arbitrarily.
    email                TEXT            NOT NULL UNIQUE,

    created_at           TIMESTAMPTZ     NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Magic-link login query: "is this email a paying customer?"
CREATE INDEX idx_customers_email ON customers (email);
