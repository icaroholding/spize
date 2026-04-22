//! Database access for the `agent_keys` rotation-history table and the
//! `rotate_key_nonces` replay-protection table.
//!
//! See `migrations/20260423000001_agent_keys.sql` for schema and the
//! per-column invariants. The verification path for every signed
//! recipient action (download, ack, inbox, request_ticket) goes through
//! [`valid_keys_at`] so that keys still inside their 24h grace window
//! continue to verify after a rotation (ADR-0024).

use sqlx::PgPool;
use time::OffsetDateTime;

/// Duration of the post-rotation overlap during which both old and new
/// keys verify. ADR-0024 fixes this at 24h.
pub const ROTATION_GRACE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AgentKeyRow {
    pub id: uuid::Uuid,
    pub agent_id: String,
    pub public_key_hex: String,
    pub public_key: Vec<u8>,
    pub valid_from: OffsetDateTime,
    pub valid_to: Option<OffsetDateTime>,
    pub created_at: OffsetDateTime,
}

/// Return every raw 32-byte public key that is valid for `agent_id` at
/// `at`. Convenience wrapper around [`valid_keys_at`] used by signature-
/// verifying handlers that want to try each candidate key without
/// caring about the surrounding metadata.
pub async fn valid_public_keys_at(
    pool: &PgPool,
    agent_id: &str,
    at: OffsetDateTime,
) -> Result<Vec<Vec<u8>>, sqlx::Error> {
    let rows = valid_keys_at(pool, agent_id, at).await?;
    Ok(rows.into_iter().map(|r| r.public_key).collect())
}

/// Return every key that is valid for `agent_id` at `at`. A key is
/// "valid" if `valid_from <= at` AND (`valid_to IS NULL` OR `valid_to > at`).
/// During the 24h rotation grace this returns two rows; outside any
/// grace it returns exactly one (the current key).
pub async fn valid_keys_at(
    pool: &PgPool,
    agent_id: &str,
    at: OffsetDateTime,
) -> Result<Vec<AgentKeyRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentKeyRow>(
        r#"
        SELECT id, agent_id, public_key_hex, public_key, valid_from, valid_to, created_at
        FROM agent_keys
        WHERE agent_id = $1
          AND valid_from <= $2
          AND (valid_to IS NULL OR valid_to > $2)
        ORDER BY valid_from DESC
        "#,
    )
    .bind(agent_id)
    .bind(at)
    .fetch_all(pool)
    .await
}

/// Return the CURRENT key for `agent_id`: the single row with
/// `valid_to IS NULL`. This is what the rotation handler verifies
/// against — the CURRENT key must authorise the rotation, not a key
/// still in its grace window.
pub async fn current_key(
    pool: &PgPool,
    agent_id: &str,
) -> Result<Option<AgentKeyRow>, sqlx::Error> {
    sqlx::query_as::<_, AgentKeyRow>(
        r#"
        SELECT id, agent_id, public_key_hex, public_key, valid_from, valid_to, created_at
        FROM agent_keys
        WHERE agent_id = $1
          AND valid_to IS NULL
        "#,
    )
    .bind(agent_id)
    .fetch_optional(pool)
    .await
}

/// Atomically record a key rotation: close the current key's
/// `valid_to` window to `now + 24h` and insert the new key as the
/// current one (`valid_to = NULL`).
///
/// The caller MUST pass `expected_current_public_key_hex` — the hex
/// of the key they verified the rotation signature against. The
/// UPDATE filters on that hex, so if a concurrent caller has already
/// rotated away from it, this call's UPDATE finds zero rows and we
/// return `RowNotFound` (handler → 409 Conflict). This is what makes
/// concurrent `rotate-key` races safe: two callers can both read the
/// same "current" key out-of-transaction, both verify signatures, but
/// only one can be the FIRST to close that specific key.
///
/// Returns the freshly-inserted row on success.
pub async fn insert_rotation(
    pool: &PgPool,
    agent_id: &str,
    expected_current_public_key_hex: &str,
    new_public_key_hex: &str,
    new_public_key: &[u8],
    now: OffsetDateTime,
) -> Result<AgentKeyRow, sqlx::Error> {
    let grace_end = now + time::Duration::seconds(ROTATION_GRACE_SECS);
    let mut tx = pool.begin().await?;

    // Close the active key — but only if it is still the key the
    // caller verified against. If another rotate-key call won the
    // race, the current key has moved on and this WHERE clause
    // matches zero rows.
    let closed: u64 = sqlx::query(
        r#"
        UPDATE agent_keys
        SET valid_to = $3
        WHERE agent_id = $1
          AND public_key_hex = $2
          AND valid_to IS NULL
        "#,
    )
    .bind(agent_id)
    .bind(expected_current_public_key_hex)
    .bind(grace_end)
    .execute(&mut *tx)
    .await?
    .rows_affected();

    if closed == 0 {
        tx.rollback().await?;
        return Err(sqlx::Error::RowNotFound);
    }

    let row = sqlx::query_as::<_, AgentKeyRow>(
        r#"
        INSERT INTO agent_keys (agent_id, public_key_hex, public_key, valid_from, valid_to)
        VALUES ($1, $2, $3, $4, NULL)
        RETURNING id, agent_id, public_key_hex, public_key, valid_from, valid_to, created_at
        "#,
    )
    .bind(agent_id)
    .bind(new_public_key_hex)
    .bind(new_public_key)
    .bind(now)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(row)
}

/// Record a rotate-key nonce (one-shot replay protection). Returns
/// `Ok(true)` if the nonce was fresh, `Ok(false)` if it was already
/// consumed.
pub async fn consume_rotate_nonce(
    pool: &PgPool,
    nonce: &str,
    agent_id: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO rotate_key_nonces (nonce, agent_id)
        VALUES ($1, $2)
        ON CONFLICT (nonce) DO NOTHING
        "#,
    )
    .bind(nonce)
    .bind(agent_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected() == 1)
}

/// Classify a rotation unique-violation by constraint name.
pub fn unique_violation_field(err: &sqlx::Error) -> Option<&'static str> {
    let db_err = err.as_database_error()?;
    if db_err.code().as_deref() != Some("23505") {
        return None;
    }
    match db_err.constraint() {
        Some("agent_keys_agent_id_public_key_hex_key") => Some("agent_key"),
        Some("idx_agent_keys_one_active_per_agent") => Some("active_key_race"),
        Some("rotate_key_nonces_pkey") => Some("nonce"),
        _ => Some("unknown"),
    }
}
