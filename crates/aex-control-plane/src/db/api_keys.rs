//! Database access for the `api_keys` table (Sprint 4).
//!
//! See `migrations/20260423000002_api_keys.sql` for storage
//! invariants. Key points:
//!
//! - We store `SHA-256(plaintext)` as `key_hash`, never the
//!   plaintext. Verification is "hash the candidate, look up by
//!   hash" — an attacker with DB read access cannot authenticate as
//!   any customer.
//! - `key_prefix` (first 12 chars of plaintext) is stored in
//!   cleartext for admin UI display. It is NOT a security boundary.
//! - Tier is free-text at the DB layer; policy code validates.

use sha2::{Digest, Sha256};
use sqlx::PgPool;
use time::OffsetDateTime;

/// Row as stored in `api_keys`. The full plaintext is NEVER present
/// on this struct — it exists for a single instant inside
/// `create_returning_plaintext`, then is returned to the caller and
/// dropped.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ApiKeyRow {
    pub id: uuid::Uuid,
    pub key_hash: String,
    pub key_prefix: String,
    pub customer_id: String,
    pub name: String,
    pub tier: String,
    pub created_at: OffsetDateTime,
    pub last_used_at: Option<OffsetDateTime>,
    pub revoked_at: Option<OffsetDateTime>,
    pub usage_count: i64,
}

/// Plaintext generated at creation time. Owner returns this on the
/// response body exactly once; the CP's own copy is dropped
/// immediately after the row is inserted.
pub struct CreatedApiKey {
    pub row: ApiKeyRow,
    pub plaintext: String,
}

/// Generate a fresh plaintext key in the form
/// `aex_live_<32 hex chars>` (128 bits of CSPRNG entropy). The
/// `aex_live_` prefix borrows Stripe's `sk_live_/sk_test_`
/// convention — future work can mint `aex_test_…` keys against a
/// test-mode DB if we need sandbox. For now everything is `live`.
fn generate_plaintext() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    format!("aex_live_{}", hex::encode(buf))
}

/// Hash a plaintext key for storage/lookup. SHA-256 is intentional:
/// we don't need a slow hash (bcrypt/argon2) because the plaintext
/// has 128 bits of entropy — offline cracking a single SHA-256 hash
/// at that entropy is computationally infeasible.
pub fn hash_plaintext(plaintext: &str) -> String {
    hex::encode(Sha256::digest(plaintext.as_bytes()))
}

/// Return the first 12 chars of a plaintext key — the searchable
/// "aex_live_xxx" admin-display prefix.
fn prefix_of(plaintext: &str) -> String {
    plaintext.chars().take(12).collect()
}

/// Mint a new API key. The plaintext is on the returned
/// `CreatedApiKey` and MUST be shown to the caller exactly once; no
/// subsequent call can retrieve it.
pub async fn create_returning_plaintext(
    pool: &PgPool,
    customer_id: &str,
    name: &str,
    tier: &str,
) -> Result<CreatedApiKey, sqlx::Error> {
    let plaintext = generate_plaintext();
    let hash = hash_plaintext(&plaintext);
    let prefix = prefix_of(&plaintext);

    let row = sqlx::query_as::<_, ApiKeyRow>(
        r#"
        INSERT INTO api_keys (key_hash, key_prefix, customer_id, name, tier)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, key_hash, key_prefix, customer_id, name, tier,
                  created_at, last_used_at, revoked_at, usage_count
        "#,
    )
    .bind(&hash)
    .bind(&prefix)
    .bind(customer_id)
    .bind(name)
    .bind(tier)
    .fetch_one(pool)
    .await?;

    Ok(CreatedApiKey { row, plaintext })
}

/// List every API key visible to the admin (no per-customer
/// filter). Sorted most-recent-first so the admin UI shows fresh
/// keys at the top.
pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeyRow>(
        r#"
        SELECT id, key_hash, key_prefix, customer_id, name, tier,
               created_at, last_used_at, revoked_at, usage_count
        FROM api_keys
        ORDER BY created_at DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

/// Look up a non-revoked row by its SHA-256 hash. This is the hot
/// authentication path: the middleware hashes the plaintext the
/// caller presented and queries this function on every metered
/// request.
///
/// `WHERE revoked_at IS NULL` matches the partial
/// `idx_api_keys_active` index so the lookup stays O(log active)
/// rather than scanning revoked tombstones. Returns `None` for both
/// "no such hash" and "matching row is revoked" — the middleware
/// doesn't distinguish (both are 401 to the caller).
pub async fn find_active_by_hash(
    pool: &PgPool,
    hash: &str,
) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeyRow>(
        r#"
        SELECT id, key_hash, key_prefix, customer_id, name, tier,
               created_at, last_used_at, revoked_at, usage_count
        FROM api_keys
        WHERE key_hash = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(hash)
    .fetch_optional(pool)
    .await
}

/// Increment `usage_count` and refresh `last_used_at` for a key that
/// just authenticated a request. Called fire-and-forget from the
/// middleware (spawned on the tokio runtime) so the hot path stays
/// fast even if the UPDATE is slow or the connection pool is hot.
///
/// The counter is not strictly accurate under concurrent writes —
/// Postgres serializes each UPDATE but we lose increments if the
/// task is dropped before completion (pod restart, etc.). A ±0.1%
/// drift is fine for soft-quota enforcement; per-call billing would
/// need a proper metered-events table.
pub async fn bump_usage(pool: &PgPool, id: uuid::Uuid) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE api_keys
        SET usage_count = usage_count + 1,
            last_used_at = now()
        WHERE id = $1
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Revoke a key by `id`. Returns the updated row. Idempotent — if
/// the key is already revoked we leave `revoked_at` as it was
/// rather than bumping the timestamp forward.
pub async fn revoke(pool: &PgPool, id: uuid::Uuid) -> Result<Option<ApiKeyRow>, sqlx::Error> {
    sqlx::query_as::<_, ApiKeyRow>(
        r#"
        UPDATE api_keys
        SET revoked_at = COALESCE(revoked_at, now())
        WHERE id = $1
        RETURNING id, key_hash, key_prefix, customer_id, name, tier,
                  created_at, last_used_at, revoked_at, usage_count
        "#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[test]
    fn generated_plaintext_has_expected_shape() {
        let k = generate_plaintext();
        assert!(k.starts_with("aex_live_"));
        // "aex_live_" + 32 hex chars = 41.
        assert_eq!(k.len(), 41);
        assert!(k.chars().skip(9).all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn hash_is_deterministic_and_different_per_input() {
        let a = hash_plaintext("aex_live_aaaa");
        let b = hash_plaintext("aex_live_aaaa");
        let c = hash_plaintext("aex_live_bbbb");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), 64); // SHA-256 hex
    }

    #[test]
    fn prefix_takes_first_12_chars() {
        assert_eq!(prefix_of("aex_live_abcd1234ef56"), "aex_live_abc");
    }

    #[sqlx::test]
    async fn find_active_by_hash_returns_row_for_active_key(pool: PgPool) {
        let created = create_returning_plaintext(&pool, "cust_abc", "lookup-ok", "dev")
            .await
            .expect("create");
        let hash = hash_plaintext(&created.plaintext);

        let found = find_active_by_hash(&pool, &hash)
            .await
            .expect("query")
            .expect("row present");

        assert_eq!(found.id, created.row.id);
        assert_eq!(found.customer_id, "cust_abc");
        assert_eq!(found.tier, "dev");
        assert!(found.revoked_at.is_none());
    }

    #[sqlx::test]
    async fn find_active_by_hash_skips_revoked_rows(pool: PgPool) {
        // Proves the partial `idx_api_keys_active` filter holds: once
        // a key is revoked, the hot auth path can't see it anymore.
        let created = create_returning_plaintext(&pool, "cust_rev", "to-be-revoked", "free")
            .await
            .expect("create");
        let hash = hash_plaintext(&created.plaintext);

        revoke(&pool, created.row.id)
            .await
            .expect("revoke")
            .expect("row returned");

        let found = find_active_by_hash(&pool, &hash).await.expect("query");
        assert!(
            found.is_none(),
            "revoked key must not be returned by find_active_by_hash"
        );
    }

    #[sqlx::test]
    async fn bump_usage_increments_counter_and_sets_last_used(pool: PgPool) {
        let created = create_returning_plaintext(&pool, "cust_bump", "bumper", "dev")
            .await
            .expect("create");
        assert_eq!(created.row.usage_count, 0);
        assert!(created.row.last_used_at.is_none());

        bump_usage(&pool, created.row.id).await.expect("bump");

        let hash = hash_plaintext(&created.plaintext);
        let after = find_active_by_hash(&pool, &hash)
            .await
            .expect("query")
            .expect("row");
        assert_eq!(after.usage_count, 1);
        assert!(
            after.last_used_at.is_some(),
            "last_used_at must be populated after bump_usage"
        );
    }
}
