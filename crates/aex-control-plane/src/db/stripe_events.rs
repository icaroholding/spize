//! Transactional-inbox storage for Stripe webhook events
//! (Sprint 4 PR 6).
//!
//! The webhook handler uses this module to guarantee that retrying
//! the same event (Stripe's at-least-once delivery) never causes
//! double side-effects on `api_keys`.
//!
//! The pattern is decision #12 in `.context/network-sovereignty-plan.md`:
//!
//! 1. `BEGIN` transaction.
//! 2. `INSERT INTO stripe_events (event_id, …) ON CONFLICT DO NOTHING`.
//! 3. If the INSERT touched 0 rows (PK conflict), bail — we've
//!    already processed this event.
//! 4. Otherwise dispatch to the handler inside the same transaction
//!    (create/revoke api_keys, etc).
//! 5. `UPDATE stripe_events SET processed_at = now()`.
//! 6. `COMMIT`.
//!
//! If step 4 or 5 fails, the transaction rolls back and Stripe's
//! next retry sees a fresh (non-existent) row and can try again.

use serde_json::Value as JsonValue;
use sqlx::{Postgres, Transaction};

/// Record a freshly-received event. Returns `true` if this is the
/// first time we see `event_id` (caller should process the event),
/// `false` if we've already accepted it (caller returns 200 without
/// processing).
///
/// The INSERT is `ON CONFLICT DO NOTHING` so concurrent calls with
/// the same `event_id` collapse safely — the database's PK
/// serialization guarantees exactly one caller wins the RETURNING.
pub async fn insert_if_new(
    tx: &mut Transaction<'_, Postgres>,
    event_id: &str,
    event_type: &str,
    payload: &JsonValue,
) -> Result<bool, sqlx::Error> {
    let row: Option<(String,)> = sqlx::query_as(
        r#"
        INSERT INTO stripe_events (event_id, event_type, payload)
        VALUES ($1, $2, $3)
        ON CONFLICT (event_id) DO NOTHING
        RETURNING event_id
        "#,
    )
    .bind(event_id)
    .bind(event_type)
    .bind(payload)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row.is_some())
}

/// Stamp the event as successfully processed. Called inside the
/// same transaction as the side-effect (api_key mint/revoke) so
/// both commit atomically.
pub async fn mark_processed(
    tx: &mut Transaction<'_, Postgres>,
    event_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE stripe_events
        SET processed_at = now()
        WHERE event_id = $1
        "#,
    )
    .bind(event_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sqlx::PgPool;

    #[sqlx::test]
    async fn insert_if_new_first_call_returns_true(pool: PgPool) {
        let mut tx = pool.begin().await.expect("begin");
        let fresh = insert_if_new(&mut tx, "evt_1", "checkout.session.completed", &json!({}))
            .await
            .expect("insert");
        assert!(fresh, "first insert must be reported as new");
        tx.commit().await.expect("commit");
    }

    #[sqlx::test]
    async fn insert_if_new_duplicate_returns_false(pool: PgPool) {
        // First call inserts and commits so the second call sees the
        // row as already-present across the boundary.
        let mut tx = pool.begin().await.unwrap();
        insert_if_new(&mut tx, "evt_dup", "test.event", &json!({"n": 1}))
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let mut tx = pool.begin().await.unwrap();
        let fresh = insert_if_new(&mut tx, "evt_dup", "test.event", &json!({"n": 2}))
            .await
            .unwrap();
        assert!(
            !fresh,
            "duplicate event_id must be reported as already-seen"
        );
        tx.commit().await.unwrap();
    }

    #[sqlx::test]
    async fn mark_processed_updates_timestamp(pool: PgPool) {
        let mut tx = pool.begin().await.unwrap();
        insert_if_new(&mut tx, "evt_proc", "test.event", &json!({}))
            .await
            .unwrap();
        mark_processed(&mut tx, "evt_proc").await.unwrap();
        tx.commit().await.unwrap();

        let processed: Option<(Option<time::OffsetDateTime>,)> =
            sqlx::query_as("SELECT processed_at FROM stripe_events WHERE event_id = $1")
                .bind("evt_proc")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(
            processed.and_then(|(ts,)| ts).is_some(),
            "processed_at must be populated after mark_processed"
        );
    }
}
