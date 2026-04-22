//! Customer subscription state (Sprint 4 PR 6).
//!
//! Mirrors the Stripe subscription lifecycle into our DB via the
//! webhook handler. The customer dashboard (PR #43+) uses rows here
//! to decide whether a caller is authorized to mint api_keys and
//! what tier those keys get.
//!
//! Writes always happen inside the same transaction as the
//! `stripe_events` idempotency insert, so either the event is fully
//! processed or not at all — no "subscription updated but event not
//! marked processed" drift.

use sqlx::{Postgres, Transaction};
use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SubscriptionRow {
    pub stripe_customer_id: String,
    pub stripe_subscription_id: String,
    pub tier: String,
    pub status: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Insert or update the subscription row for this customer. Called
/// on `customer.subscription.created` and
/// `customer.subscription.updated` events. The `ON CONFLICT …
/// DO UPDATE` clause keeps the row in sync with Stripe's authoritative
/// view without requiring the caller to distinguish first-time
/// create from update.
pub async fn upsert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    stripe_customer_id: &str,
    stripe_subscription_id: &str,
    tier: &str,
    status: &str,
) -> Result<SubscriptionRow, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionRow>(
        r#"
        INSERT INTO subscriptions
            (stripe_customer_id, stripe_subscription_id, tier, status)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (stripe_customer_id) DO UPDATE SET
            stripe_subscription_id = EXCLUDED.stripe_subscription_id,
            tier = EXCLUDED.tier,
            status = EXCLUDED.status,
            updated_at = now()
        RETURNING stripe_customer_id, stripe_subscription_id, tier,
                  status, created_at, updated_at
        "#,
    )
    .bind(stripe_customer_id)
    .bind(stripe_subscription_id)
    .bind(tier)
    .bind(status)
    .fetch_one(&mut **tx)
    .await
}

/// Set `status = 'canceled'` for a given customer, if a row exists.
/// Called on `customer.subscription.deleted`. Returns `true` if a
/// row was updated (typical), `false` if no subscription existed
/// (idempotent replay of a delete event against a fresh DB).
pub async fn mark_canceled_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    stripe_customer_id: &str,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE subscriptions
        SET status = 'canceled',
            updated_at = now()
        WHERE stripe_customer_id = $1
        "#,
    )
    .bind(stripe_customer_id)
    .execute(&mut **tx)
    .await?;
    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn upsert_inserts_first_call(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        let row = upsert_in_tx(&mut tx, "cus_1", "sub_1", "dev", "active")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(row.tier, "dev");
        assert_eq!(row.status, "active");
    }

    #[sqlx::test]
    async fn upsert_updates_on_conflict(pool: PgPool) {
        // First insert.
        let mut tx = pool.begin().await.unwrap();
        upsert_in_tx(&mut tx, "cus_2", "sub_2", "dev", "active")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        // Second call with same customer_id → UPDATE, not duplicate.
        let mut tx = pool.begin().await.unwrap();
        let row = upsert_in_tx(&mut tx, "cus_2", "sub_2", "team", "active")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(row.tier, "team", "tier must reflect the latest upsert");

        // And there's still only one row for this customer.
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM subscriptions WHERE stripe_customer_id = $1")
                .bind("cus_2")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count.0, 1);
    }

    #[sqlx::test]
    async fn mark_canceled_flips_status(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        upsert_in_tx(&mut tx, "cus_3", "sub_3", "dev", "active")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        let updated = mark_canceled_in_tx(&mut tx, "cus_3").await.unwrap();
        tx.commit().await.unwrap();
        assert!(updated, "mark_canceled must report success when row exists");

        let status: (String,) =
            sqlx::query_as("SELECT status FROM subscriptions WHERE stripe_customer_id = $1")
                .bind("cus_3")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(status.0, "canceled");
    }

    #[sqlx::test]
    async fn mark_canceled_on_missing_row_returns_false(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        let updated = mark_canceled_in_tx(&mut tx, "cus_missing").await.unwrap();
        tx.commit().await.unwrap();
        assert!(!updated);
    }
}
