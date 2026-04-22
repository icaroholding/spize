-- Sprint 4 (revenue): customer-facing API keys.
--
-- An api_key is the capability a paying customer presents on every
-- request to the control plane that goes beyond the signed-wire
-- protocol (e.g. dashboards, admin-light views, quota-enforced
-- endpoints). Keys are minted by ops via the admin API or — once
-- Stripe lands — by the checkout webhook after a successful
-- subscription event.
--
-- Storage invariants:
--
-- - **Never store the plaintext.** We store SHA-256(key) as
--   `key_hash` only. The full key is shown to the operator ONCE at
--   creation time and can't be retrieved again. Lost keys are
--   replaced via rotation, not recovered.
-- - **key_prefix is searchable.** First 12 chars of the plaintext
--   (e.g. `aex_live_abc1`) are stored in cleartext so admin UIs can
--   let ops identify a key by the shorthand a customer pastes into
--   a support ticket, without having to hash-compare.
-- - **tier is free-text on purpose.** Enforcing a CHECK constraint
--   here would require a schema migration every time we launch a
--   new plan. Policy code already validates `dev|team|enterprise`
--   at the boundary; storing arbitrary strings is forward-compat.

CREATE TABLE api_keys (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- SHA-256 of the full key, hex-encoded (64 chars). UNIQUE so
    -- `WHERE key_hash = $1` is the lookup path at request time.
    key_hash        TEXT            NOT NULL UNIQUE,

    -- First 12 chars of the plaintext, stored for admin-UI display
    -- only. Never used for auth — the hash is authoritative.
    key_prefix      TEXT            NOT NULL,

    -- Opaque customer identifier. At mint time it's whatever the
    -- admin passed (typically a Stripe customer_id once billing is
    -- live, or an email / UUID for grandfathered alpha users).
    -- Indexed for the "list all keys for this customer" query.
    customer_id     TEXT            NOT NULL,

    -- Human-readable label ("production server A", "local dev",
    -- etc.). Customers see this in the future dashboard.
    name            TEXT            NOT NULL,

    -- Subscription tier the key is bound to. Policy code maps this
    -- to quotas. Deliberately TEXT (see header comment).
    tier            TEXT            NOT NULL DEFAULT 'free',

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,

    -- Running counter of successful requests authenticated by this
    -- key. Not strictly accurate under concurrent writes (we
    -- accept races — ±0.1% drift is fine for soft-quota
    -- enforcement) but monotonically increases. Replaced by a
    -- proper metered-events table if we need per-call billing.
    usage_count     BIGINT          NOT NULL DEFAULT 0
);

CREATE INDEX idx_api_keys_customer_id ON api_keys (customer_id);
-- Lookup-at-request path: key presented → sha256 → this index.
-- The PRIMARY KEY already indexes `id`; this partial index on
-- non-revoked rows keeps the hot auth path off revoked tombstones.
CREATE INDEX idx_api_keys_active ON api_keys (key_hash) WHERE revoked_at IS NULL;
