//! `POST /v1/inbox` — agent pulls the list of transfers waiting for them.
//!
//! Requires the agent to sign a canonical `transfer_receipt_bytes` with
//! `action = "inbox"` and `transfer_id = "inbox"` as a literal marker.
//! The signature proves the caller is the agent whose inbox they're
//! querying (we don't want to leak transfer metadata to unauthenticated
//! probes).

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use aex_core::wire::{transfer_receipt_bytes, MAX_NONCE_LEN, MIN_NONCE_LEN};
use aex_core::AgentId;

use crate::{db::transfers as tx_db, error::ApiError, AppState};

const INBOX_TRANSFER_MARKER: &str = "inbox";
/// Cap how many rows we return per call — protects both server memory and
/// the audit log. Clients that expect more pages can add pagination later.
const INBOX_LIMIT: i64 = 100;

pub fn router() -> Router<AppState> {
    Router::new().route("/inbox", post(list_inbox))
}

#[derive(Debug, Deserialize)]
pub struct InboxRequest {
    pub recipient_agent_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct InboxEntry {
    pub transfer_id: String,
    pub sender_agent_id: String,
    pub state: String,
    pub size_bytes: u64,
    pub declared_mime: Option<String>,
    pub filename: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Serialize)]
pub struct InboxResponse {
    pub agent_id: String,
    pub count: usize,
    pub entries: Vec<InboxEntry>,
}

async fn list_inbox(
    State(state): State<AppState>,
    Json(req): Json<InboxRequest>,
) -> Result<Json<InboxResponse>, ApiError> {
    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest("nonce length out of range".into()));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }
    let now_unix = state.clock.now_unix();
    if !aex_core::wire::is_within_clock_skew(now_unix, req.issued_at) {
        return Err(ApiError::BadRequest(
            "issued_at outside allowed skew".into(),
        ));
    }

    let recipient = AgentId::new(&req.recipient_agent_id)?;

    let canonical = transfer_receipt_bytes(
        recipient.as_str(),
        INBOX_TRANSFER_MARKER,
        "inbox",
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("canonical: {}", e)))?;

    let sig_bytes = hex::decode(&req.signature_hex)
        .map_err(|e| ApiError::BadRequest(format!("signature_hex: {}", e)))?;

    crate::verify::verify_with_valid_keys(
        &state.db,
        recipient.as_str(),
        state.clock.now(),
        &canonical,
        &sig_bytes,
    )
    .await?;

    let rows = tx_db::list_inbox(&state.db, recipient.as_str(), INBOX_LIMIT).await?;
    let entries: Vec<InboxEntry> = rows
        .into_iter()
        .map(|r| InboxEntry {
            transfer_id: r.transfer_id,
            sender_agent_id: r.sender_agent_id,
            state: r.state,
            size_bytes: r.size_bytes as u64,
            declared_mime: r.declared_mime,
            filename: r.filename,
            created_at: r.created_at,
        })
        .collect();

    Ok(Json(InboxResponse {
        agent_id: recipient.to_string(),
        count: entries.len(),
        entries,
    }))
}
