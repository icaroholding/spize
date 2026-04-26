//! Magic-link token storage (Sprint 4 PR 7).
//!
//! Single-use, short-lived bearer tokens that prove a customer
//! controls the email address they typed in. The plaintext travels
//! in the customer's inbox — we store only `SHA-256(plaintext)` so
//! a DB read does not give an attacker valid login material.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MagicLinkRow {
    pub id: uuid::Uuid,
    pub token_hash: String,
    pub stripe_customer_id: String,
    pub email: String,
    pub created_at: OffsetDateTime,
    pub used_at: Option<OffsetDateTime>,
    pub expires_at: OffsetDateTime,
}

/// Generate a fresh plaintext token: 32 bytes of CSPRNG entropy
/// hex-encoded. The result is 64 chars; we don't include a prefix
/// because the token never lives anywhere except inside a URL
/// fragment a customer just received.
pub fn generate_plaintext() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Hash a plaintext token for storage / lookup. SHA-256 is right
/// here for the same reason as `api_keys`: 256 bits of entropy
/// makes offline cracking infeasible without slow-hashing CPU
/// cost.
pub fn hash_plaintext(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

/// Mint a magic-link token row. Returns the inserted row + the
/// plaintext (which the caller must email to the customer; the DB
/// holds only the hash).
pub async fn create(
    pool: &PgPool,
    stripe_customer_id: &str,
    email: &str,
    ttl: time::Duration,
    now: OffsetDateTime,
) -> Result<(MagicLinkRow, String), sqlx::Error> {
    let plaintext = generate_plaintext();
    let token_hash = hash_plaintext(&plaintext);
    let expires_at = now + ttl;

    let row = sqlx::query_as::<_, MagicLinkRow>(
        r#"
        INSERT INTO magic_link_tokens
            (token_hash, stripe_customer_id, email, expires_at)
        VALUES ($1, $2, $3, $4)
        RETURNING id, token_hash, stripe_customer_id, email,
                  created_at, used_at, expires_at
        "#,
    )
    .bind(&token_hash)
    .bind(stripe_customer_id)
    .bind(email.trim().to_ascii_lowercase())
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok((row, plaintext))
}

/// Outcome of a `consume` call. The state machine has three valid
/// resting states the verify endpoint must distinguish on the wire.
#[derive(Debug)]
pub enum ConsumeOutcome {
    /// Plaintext was found, fresh, and not yet used. The row was
    /// stamped used_at = now() and the caller now holds the only
    /// valid claim to a session for that customer.
    Consumed(MagicLinkRow),
    /// Token doesn't match any row. Could be a typo, an attacker,
    /// or a token someone already pruned.
    NotFound,
    /// Token matched a row but expires_at is in the past.
    Expired,
    /// Token matched a row and used_at is non-null. Single-use
    /// invariant fired.
    AlreadyUsed,
}

/// Atomically validate + mark-used a plaintext token. Idempotency
/// note: the UPDATE is conditional on `used_at IS NULL`, so two
/// concurrent verify calls collapse to exactly one Consumed and one
/// AlreadyUsed.
pub async fn consume(
    pool: &PgPool,
    plaintext: &str,
    now: OffsetDateTime,
) -> Result<ConsumeOutcome, sqlx::Error> {
    let token_hash = hash_plaintext(plaintext);

    // Conditional UPDATE: stamp `used_at` only when the row is
    // both not-yet-used AND not-yet-expired. RETURNING gives us
    // the row when the UPDATE actually fired; otherwise we
    // separately query to distinguish "not found" / "expired" /
    // "already used".
    let consumed = sqlx::query_as::<_, MagicLinkRow>(
        r#"
        UPDATE magic_link_tokens
        SET used_at = $2
        WHERE token_hash = $1
          AND used_at IS NULL
          AND expires_at > $2
        RETURNING id, token_hash, stripe_customer_id, email,
                  created_at, used_at, expires_at
        "#,
    )
    .bind(&token_hash)
    .bind(now)
    .fetch_optional(pool)
    .await?;

    if let Some(row) = consumed {
        return Ok(ConsumeOutcome::Consumed(row));
    }

    // UPDATE did nothing — figure out why.
    let row: Option<MagicLinkRow> = sqlx::query_as(
        r#"
        SELECT id, token_hash, stripe_customer_id, email,
               created_at, used_at, expires_at
        FROM magic_link_tokens
        WHERE token_hash = $1
        "#,
    )
    .bind(&token_hash)
    .fetch_optional(pool)
    .await?;

    match row {
        None => Ok(ConsumeOutcome::NotFound),
        Some(r) if r.used_at.is_some() => Ok(ConsumeOutcome::AlreadyUsed),
        Some(r) if r.expires_at <= now => Ok(ConsumeOutcome::Expired),
        // Defensive — shouldn't happen given the UPDATE filter.
        Some(_) => Ok(ConsumeOutcome::NotFound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::customers;

    async fn seed_customer(pool: &PgPool, customer_id: &str, email: &str) {
        let mut tx = pool.begin().await.unwrap();
        customers::upsert_in_tx(&mut tx, customer_id, email)
            .await
            .unwrap();
        tx.commit().await.unwrap();
    }

    #[test]
    fn generate_plaintext_has_64_hex_chars() {
        let t = generate_plaintext();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_plaintext("abc"), hash_plaintext("abc"));
        assert_ne!(hash_plaintext("abc"), hash_plaintext("def"));
    }

    #[sqlx::test]
    async fn consume_round_trip(pool: PgPool) {
        seed_customer(&pool, "cus_a", "a@example.com").await;
        let now = OffsetDateTime::now_utc();
        let (row, plaintext) = create(
            &pool,
            "cus_a",
            "a@example.com",
            time::Duration::minutes(15),
            now,
        )
        .await
        .unwrap();
        assert!(row.used_at.is_none());

        let outcome = consume(&pool, &plaintext, now + time::Duration::minutes(1))
            .await
            .unwrap();
        match outcome {
            ConsumeOutcome::Consumed(r) => assert_eq!(r.stripe_customer_id, "cus_a"),
            other => panic!("expected Consumed, got {other:?}"),
        }
    }

    #[sqlx::test]
    async fn consume_rejects_unknown_token(pool: PgPool) {
        let outcome = consume(&pool, "deadbeef", OffsetDateTime::now_utc())
            .await
            .unwrap();
        assert!(matches!(outcome, ConsumeOutcome::NotFound));
    }

    #[sqlx::test]
    async fn consume_rejects_expired(pool: PgPool) {
        seed_customer(&pool, "cus_e", "e@example.com").await;
        let then = OffsetDateTime::now_utc();
        let (_, plaintext) = create(
            &pool,
            "cus_e",
            "e@example.com",
            time::Duration::minutes(15),
            then,
        )
        .await
        .unwrap();
        // Try to consume 20 minutes later — past expiry.
        let outcome = consume(&pool, &plaintext, then + time::Duration::minutes(20))
            .await
            .unwrap();
        assert!(matches!(outcome, ConsumeOutcome::Expired));
    }

    #[sqlx::test]
    async fn consume_is_single_use(pool: PgPool) {
        seed_customer(&pool, "cus_u", "u@example.com").await;
        let now = OffsetDateTime::now_utc();
        let (_, plaintext) = create(
            &pool,
            "cus_u",
            "u@example.com",
            time::Duration::minutes(15),
            now,
        )
        .await
        .unwrap();

        // First consume succeeds.
        let first = consume(&pool, &plaintext, now + time::Duration::seconds(1))
            .await
            .unwrap();
        assert!(matches!(first, ConsumeOutcome::Consumed(_)));

        // Second consume reports already-used, NOT consumed again.
        let second = consume(&pool, &plaintext, now + time::Duration::seconds(2))
            .await
            .unwrap();
        assert!(matches!(second, ConsumeOutcome::AlreadyUsed));
    }
}
