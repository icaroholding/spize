-- Sprint 4 PR 7: magic-link login tokens.
--
-- A magic link is a single-use, short-lived bearer token a customer
-- presents (via clicking a link in their email) to start a session.
-- The dashboard's "log in" form takes an email, the backend mints a
-- row here, mails the link, and the customer's click verifies the
-- token + sets a session cookie.
--
-- Storage invariants:
--
-- - **Hashed.** We store SHA-256(token) as `token_hash`, never the
--   plaintext. An attacker with DB read access cannot use a
--   pending magic link as a login.
-- - **Single-use.** `used_at` is set on first verify. Subsequent
--   attempts to use the same token fail.
-- - **Time-bounded.** `expires_at` is set ~15 minutes after
--   creation. The verify endpoint refuses past-expiry tokens even
--   if `used_at` is still null.

CREATE TABLE magic_link_tokens (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- SHA-256 of the plaintext token, hex-encoded (64 chars). The
    -- plaintext is in the user's email; we never store it.
    token_hash      TEXT            NOT NULL UNIQUE,

    -- The customer this token resolves a session for. References
    -- `customers` so the FK ensures we never mint a magic link for
    -- a non-existent customer (webhook lag would surface as a
    -- caller-visible error, not a dangling row).
    stripe_customer_id  TEXT        NOT NULL REFERENCES customers(stripe_customer_id),

    -- Lower-cased email the request was made with. Pinned at mint
    -- time so a later email change on the customer record doesn't
    -- silently change which email could be used to log in.
    email           TEXT            NOT NULL,

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    -- Set on the first successful `verify` call. NULL = still
    -- redeemable; non-NULL = already used (idempotent: second
    -- verify returns the same session as the first).
    used_at         TIMESTAMPTZ,

    expires_at      TIMESTAMPTZ     NOT NULL
);

-- Reaper / observability: "any unused tokens older than 24h?"
CREATE INDEX idx_magic_link_tokens_expires ON magic_link_tokens (expires_at);

-- Per-customer query: "rate-limit magic-link requests for this
-- customer" (used in PR #44+).
CREATE INDEX idx_magic_link_tokens_customer ON magic_link_tokens (stripe_customer_id, created_at DESC);
