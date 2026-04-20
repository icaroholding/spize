//! Database access for the `transfers` and `transfer_intent_nonces`
//! tables. See `migrations/20260420000002_transfers.sql`.

use serde_json::Value as JsonValue;
use sqlx::PgPool;
use time::OffsetDateTime;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TransferRow {
    pub id: uuid::Uuid,
    pub transfer_id: String,
    pub sender_agent_id: String,
    pub recipient: String,
    pub recipient_kind: String,
    pub state: String,
    pub size_bytes: i64,
    pub declared_mime: Option<String>,
    pub filename: Option<String>,
    pub blob_sha256: Option<String>,
    pub blob_path: Option<String>,
    pub scanner_verdict: Option<JsonValue>,
    pub policy_decision: Option<JsonValue>,
    pub created_at: OffsetDateTime,
    pub scanned_at: Option<OffsetDateTime>,
    pub accepted_at: Option<OffsetDateTime>,
    pub delivered_at: Option<OffsetDateTime>,
    pub rejected_at: Option<OffsetDateTime>,
    pub rejection_code: Option<String>,
    pub rejection_reason: Option<String>,
    pub tunnel_url: Option<String>,
}

pub struct InsertTransfer<'a> {
    pub transfer_id: &'a str,
    pub sender_agent_id: &'a str,
    pub recipient: &'a str,
    pub recipient_kind: &'a str,
    pub state: &'a str,
    pub size_bytes: i64,
    pub declared_mime: Option<&'a str>,
    pub filename: Option<&'a str>,
    pub blob_sha256: Option<&'a str>,
    pub scanner_verdict: Option<JsonValue>,
    pub policy_decision: Option<JsonValue>,
    pub rejection_code: Option<&'a str>,
    pub tunnel_url: Option<&'a str>,
    pub rejection_reason: Option<&'a str>,
}

pub async fn insert(pool: &PgPool, t: InsertTransfer<'_>) -> Result<TransferRow, sqlx::Error> {
    let scanned_at = if t.scanner_verdict.is_some() {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };
    let rejected_at = if t.rejection_code.is_some() {
        Some(OffsetDateTime::now_utc())
    } else {
        None
    };

    sqlx::query_as::<_, TransferRow>(
        r#"
        INSERT INTO transfers (
            transfer_id, sender_agent_id, recipient, recipient_kind,
            state, size_bytes, declared_mime, filename, blob_sha256,
            scanner_verdict, policy_decision,
            scanned_at, rejected_at, rejection_code, rejection_reason, tunnel_url
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
        RETURNING id, transfer_id, sender_agent_id, recipient, recipient_kind,
                  state, size_bytes, declared_mime, filename, blob_sha256, blob_path,
                  scanner_verdict, policy_decision,
                  created_at, scanned_at, accepted_at, delivered_at, rejected_at,
                  rejection_code, rejection_reason, tunnel_url
        "#,
    )
    .bind(t.transfer_id)
    .bind(t.sender_agent_id)
    .bind(t.recipient)
    .bind(t.recipient_kind)
    .bind(t.state)
    .bind(t.size_bytes)
    .bind(t.declared_mime)
    .bind(t.filename)
    .bind(t.blob_sha256)
    .bind(t.scanner_verdict)
    .bind(t.policy_decision)
    .bind(scanned_at)
    .bind(rejected_at)
    .bind(t.rejection_code)
    .bind(t.rejection_reason)
    .bind(t.tunnel_url)
    .fetch_one(pool)
    .await
}

pub async fn find_by_transfer_id(
    pool: &PgPool,
    transfer_id: &str,
) -> Result<Option<TransferRow>, sqlx::Error> {
    sqlx::query_as::<_, TransferRow>(
        r#"
        SELECT id, transfer_id, sender_agent_id, recipient, recipient_kind,
               state, size_bytes, declared_mime, filename, blob_sha256, blob_path,
               scanner_verdict, policy_decision,
               created_at, scanned_at, accepted_at, delivered_at, rejected_at,
               rejection_code, rejection_reason
        FROM transfers
        WHERE transfer_id = $1
        "#,
    )
    .bind(transfer_id)
    .fetch_optional(pool)
    .await
}

pub async fn mark_accepted(pool: &PgPool, transfer_id: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE transfers SET state = 'accepted', accepted_at = now() \
         WHERE transfer_id = $1 AND state = 'ready_for_pickup'",
    )
    .bind(transfer_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn mark_delivered(pool: &PgPool, transfer_id: &str) -> Result<u64, sqlx::Error> {
    let res = sqlx::query(
        "UPDATE transfers SET state = 'delivered', delivered_at = now() \
         WHERE transfer_id = $1 AND state IN ('accepted','ready_for_pickup')",
    )
    .bind(transfer_id)
    .execute(pool)
    .await?;
    Ok(res.rows_affected())
}

pub async fn list_inbox(
    pool: &PgPool,
    recipient: &str,
    limit: i64,
) -> Result<Vec<TransferRow>, sqlx::Error> {
    sqlx::query_as::<_, TransferRow>(
        r#"
        SELECT id, transfer_id, sender_agent_id, recipient, recipient_kind,
               state, size_bytes, declared_mime, filename, blob_sha256, blob_path,
               scanner_verdict, policy_decision,
               created_at, scanned_at, accepted_at, delivered_at, rejected_at,
               rejection_code, rejection_reason
        FROM transfers
        WHERE recipient = $1
          AND state IN ('ready_for_pickup','accepted')
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(recipient)
    .bind(limit)
    .fetch_all(pool)
    .await
}

pub async fn consume_intent_nonce(
    pool: &PgPool,
    nonce: &str,
    agent_id: &str,
) -> Result<bool, sqlx::Error> {
    let res = sqlx::query(
        r#"
        INSERT INTO transfer_intent_nonces (nonce, agent_id)
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
