-- Sprint 4 (revenue): Stripe webhook idempotency inbox.
--
-- Pattern: "transactional inbox + idempotency key" (decision #12 in
-- network-sovereignty-plan.md).
--
-- On every webhook call we INSERT the event into this table inside
-- the same transaction that mutates api_keys. If Stripe retries the
-- same event (server crashed / slow / network glitch), the PK
-- conflict makes the second INSERT a no-op and we return 200
-- without double-processing.
--
-- Payload is kept in JSONB so that operators can reconstruct the
-- exact event body later (audit, debugging, re-replay) without
-- having to hit the Stripe API. Retention is out-of-scope for now;
-- a future migration can add a cleanup policy once volume matters.

CREATE TABLE stripe_events (
    -- Stripe's own event.id (e.g. `evt_1N…`). Unique across an
    -- account's entire history — safe as a primary key.
    event_id      TEXT            PRIMARY KEY,

    -- Event type string (e.g. `checkout.session.completed`). Stored
    -- separately from the payload so the dispatcher can route
    -- without re-parsing JSON on idempotent replays.
    event_type    TEXT            NOT NULL,

    -- Raw event body as received. JSONB lets us index / query later
    -- (e.g. "show me all events for customer X") without migrating.
    payload       JSONB           NOT NULL,

    received_at   TIMESTAMPTZ     NOT NULL DEFAULT now(),

    -- When the event was successfully handled (api_key minted,
    -- revoked, etc.). NULL if the transaction committed the INSERT
    -- but processing failed downstream — lets us run a reaper job
    -- later that surfaces unprocessed events without re-hitting
    -- Stripe. In the happy path, INSERT and UPDATE-processed_at are
    -- in the same transaction so this is non-null on commit.
    processed_at  TIMESTAMPTZ
);

-- Operator query: "which events landed in the last hour?"
CREATE INDEX idx_stripe_events_received_at ON stripe_events (received_at DESC);

-- Reaper query: "any events we committed but didn't process?"
-- Partial index keeps this tight even as the table grows.
CREATE INDEX idx_stripe_events_unprocessed ON stripe_events (received_at)
    WHERE processed_at IS NULL;
