//! Customer email registry (Sprint 4 PR 7).
//!
//! Maps `stripe_customer_id ↔ email` so the magic-link login flow
//! can resolve an email back to the Stripe customer record.
//! Populated entirely by the `customer.created` /
//! `customer.updated` webhook handlers — there is no admin write
//! path today.

use sqlx::{PgPool, Postgres, Transaction};
use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CustomerRow {
    pub stripe_customer_id: String,
    pub email: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Insert or update a customer row, called by the Stripe webhook
/// inside the same transaction as the `stripe_events` idempotency
/// insert. Email is lower-cased so the magic-link `find_by_email`
/// is case-insensitive.
///
/// ON CONFLICT on `stripe_customer_id`: update email + bump
/// updated_at. ON CONFLICT on the `email` UNIQUE constraint (rare —
/// only when two distinct Stripe customers share the same address):
/// the INSERT fails and the caller must decide whether to log + skip
/// or surface — see the webhook handler for that policy.
pub async fn upsert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    stripe_customer_id: &str,
    email: &str,
) -> Result<CustomerRow, sqlx::Error> {
    let normalized = email.trim().to_ascii_lowercase();
    sqlx::query_as::<_, CustomerRow>(
        r#"
        INSERT INTO customers (stripe_customer_id, email)
        VALUES ($1, $2)
        ON CONFLICT (stripe_customer_id) DO UPDATE SET
            email = EXCLUDED.email,
            updated_at = now()
        RETURNING stripe_customer_id, email, created_at, updated_at
        "#,
    )
    .bind(stripe_customer_id)
    .bind(&normalized)
    .fetch_one(&mut **tx)
    .await
}

/// Resolve an email to a `(stripe_customer_id, email)` pair. Used
/// by the magic-link request endpoint to decide whether the email
/// belongs to a known customer (and thus deserves a real link in
/// their inbox vs. a silent 200 for privacy).
pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<CustomerRow>, sqlx::Error> {
    let normalized = email.trim().to_ascii_lowercase();
    sqlx::query_as::<_, CustomerRow>(
        r#"
        SELECT stripe_customer_id, email, created_at, updated_at
        FROM customers
        WHERE email = $1
        "#,
    )
    .bind(&normalized)
    .fetch_optional(pool)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test]
    async fn upsert_inserts_first_call(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        let row = upsert_in_tx(&mut tx, "cus_1", "Foo@Example.com")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(row.stripe_customer_id, "cus_1");
        assert_eq!(row.email, "foo@example.com", "email must be lower-cased");
    }

    #[sqlx::test]
    async fn upsert_updates_email_on_conflict(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        upsert_in_tx(&mut tx, "cus_2", "old@example.com")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        let row = upsert_in_tx(&mut tx, "cus_2", "new@example.com")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(row.email, "new@example.com");
    }

    #[sqlx::test]
    async fn find_by_email_is_case_insensitive(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        upsert_in_tx(&mut tx, "cus_ci", "case@example.com")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let row = find_by_email(&pool, "CASE@Example.COM")
            .await
            .unwrap()
            .expect("must find by mixed case");
        assert_eq!(row.stripe_customer_id, "cus_ci");
    }

    #[sqlx::test]
    async fn find_by_email_returns_none_for_unknown(pool: PgPool) {
        let row = find_by_email(&pool, "nobody@example.com").await.unwrap();
        assert!(row.is_none());
    }
}
