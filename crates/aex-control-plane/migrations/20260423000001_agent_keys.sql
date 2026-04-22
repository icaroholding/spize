-- Sprint 2 (v1.3.0-beta.1): formal key rotation per ADR-0024.
--
-- An agent's identity (`spize:org/name:fingerprint`) outlives any single
-- Ed25519 keypair. Rotation is a deliberate operation signed by the
-- OUTGOING key that declares a new public key; the control plane honours
-- both keys for a 24h grace window before the old one stops verifying.
--
-- Per decision 4B (Sprint 2 plan-eng-review 2026-04-21), history lives in
-- its own table rather than denormalized columns on `agents`. Keeping the
-- rotation ledger separate means:
--   - Verification handlers query by validity window without touching the
--     primary agent row.
--   - Audit queries ("show me every key this agent has ever held") are a
--     simple SELECT, not a JSONB walk.
--   - Future multi-active-keys scenarios (planned re-key without downtime)
--     slot in without another migration.
--
-- Shape invariants:
--   - (agent_id, public_key_hex) is UNIQUE — retries of the same rotation
--     collapse to one row and concurrent races get a deterministic
--     409 Conflict on the loser (piggyback for TODO-2 concurrent test).
--   - `valid_from` is the instant the CP recorded the rotation.
--   - `valid_to` is NULL while the key is the CURRENT key; a finite value
--     means the key has been superseded and will stop verifying at that
--     instant (24h after the successor's `valid_from`).
--   - Exactly zero or one row per agent_id has `valid_to IS NULL` at any
--     time. The rotation handler enforces this transactionally by UPDATE-
--     ing the previous current row to set `valid_to = new.valid_from + 24h`
--     inside the same transaction that INSERTs the new one.

CREATE TABLE agent_keys (
    id              UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Canonical agent_id the key belongs to. Kept as a denormalized TEXT
    -- rather than an FK to `agents(agent_id)` to avoid cascading
    -- availability concerns if the `agents` row is ever archived.
    agent_id        TEXT            NOT NULL,

    -- Hex-encoded Ed25519 public key. We store as hex rather than BYTEA
    -- so lookups by the canonical wire form are a direct string compare
    -- with no encoding hop.
    public_key_hex  TEXT            NOT NULL,

    -- Raw 32-byte public key. Needed for ed25519-dalek's VerifyingKey
    -- without re-decoding from hex on every request.
    public_key      BYTEA           NOT NULL,

    valid_from      TIMESTAMPTZ     NOT NULL,
    valid_to        TIMESTAMPTZ,

    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now(),

    UNIQUE (agent_id, public_key_hex)
);

CREATE INDEX idx_agent_keys_agent_id ON agent_keys (agent_id);
-- Fast path for "which keys are currently active for agent X?" Covers
-- both the rotation handler's single-row probe (valid_to IS NULL) and
-- the grace-window bounded scan in valid_keys_at, where the outer
-- index lookup narrows to the agent and the additional filter on
-- valid_to is applied post-scan.
CREATE INDEX idx_agent_keys_valid_to ON agent_keys (agent_id, valid_to);
-- HARD INVARIANT: at most one row per agent has valid_to IS NULL (the
-- current key). Two concurrent rotate-key calls can both pass the
-- handler's "is this the current key?" check; without this index they
-- could each UPDATE a different row (one closes the original, the
-- other closes the first-inserted successor) and both end up
-- INSERTing — leaving two "current" rows for the same agent. The
-- partial unique index makes that outcome impossible: the loser gets
-- a 23505 on INSERT, which the handler maps to 409 Conflict.
CREATE UNIQUE INDEX idx_agent_keys_one_active_per_agent
    ON agent_keys (agent_id)
    WHERE valid_to IS NULL;

-- Backfill: every already-registered agent's current key becomes its
-- first row here, with NULL valid_to (= still current) and valid_from =
-- the agent's registration time. This is what lets the grace-period
-- verifier treat pre-rotation traffic identically to post-rotation
-- traffic — no special-case for "never rotated" agents.
INSERT INTO agent_keys (agent_id, public_key_hex, public_key, valid_from, valid_to, created_at)
SELECT
    agent_id,
    encode(public_key, 'hex'),
    public_key,
    created_at,
    NULL,
    created_at
FROM agents;

-- Rotation challenge nonces — single-use. Same shape as
-- `registration_nonces`: seen-before means replay, even with a fresh
-- timestamp. Pruning is deferred to the same future job that prunes
-- registration_nonces.
CREATE TABLE rotate_key_nonces (
    nonce           TEXT            PRIMARY KEY,
    agent_id        TEXT            NOT NULL,
    consumed_at     TIMESTAMPTZ     NOT NULL DEFAULT now()
);
