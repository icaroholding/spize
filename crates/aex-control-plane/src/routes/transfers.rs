//! Transfer endpoints — the core AEX flow.
//!
//! # Wire protocol (M1)
//!
//! Upload in one request (sender provides intent + bytes), recipient polls
//! status, downloads blob with its own signed challenge, and acks delivery.
//!
//! 1. **POST /v1/transfers** (sender) — body: `{sender_agent_id, recipient,
//!    declared_mime, filename, nonce, issued_at, intent_signature_hex,
//!    blob_hex}`. Server verifies sender, runs pre-scan policy, scans,
//!    runs post-scan policy, persists verdict + (on allow) stores blob,
//!    audit-logs each stage, returns `{transfer_id, state, verdict}`.
//! 2. **GET /v1/transfers/:id** — status. Anyone holding the transfer_id
//!    can check; the transfer_id itself is the capability.
//! 3. **POST /v1/transfers/:id/download** (recipient) — body:
//!    `{recipient_agent_id, nonce, issued_at, signature_hex}` over the
//!    canonical `transfer_receipt_bytes(…action="download"…)`. Server
//!    verifies signature, returns the blob bytes (base64). State moves
//!    to `accepted`.
//! 4. **POST /v1/transfers/:id/ack** (recipient) — body: same shape,
//!    action = `ack`. State moves to `delivered`, audit entry with the
//!    signed receipt.

#![allow(clippy::too_many_arguments)]

use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use std::sync::Arc;

use aex_audit::{AuditLog, Event, EventKind};
use aex_core::wire::{transfer_intent_bytes, transfer_receipt_bytes, MAX_NONCE_LEN, MIN_NONCE_LEN};
use aex_core::AgentId;
use aex_policy::{PolicyDecision, PolicyRequest, RecipientKind};
use aex_scanner::{PipelineVerdict, ScanInput};

use crate::{
    db::{agents as agents_db, transfers as tx_db},
    error::ApiError,
    AppState,
};

const SIGNATURE_LEN: usize = 64;
const PUBLIC_KEY_LEN: usize = 32;

/// Append to the audit log, logging (but not propagating) errors.
///
/// We treat audit writes as advisory on the transfer happy-path: we'd
/// rather deliver a file and lose an event than fail the delivery on an
/// audit blip. Errors are logged so observability catches persistent
/// failures. The `ack` path is the exception — it explicitly returns
/// the chain head and therefore surfaces any audit error to the caller.
async fn audit_warn(audit: &Arc<dyn AuditLog>, event: Event) {
    if let Err(e) = audit.append(event).await {
        tracing::warn!(
            target: "aex_control_plane::audit",
            error = %e,
            "audit append failed (transfer continues; audit is advisory on this path)"
        );
    }
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", post(create_transfer))
        .route("/:transfer_id", get(get_transfer))
        .route("/:transfer_id/download", post(download_transfer))
        .route("/:transfer_id/ack", post(ack_transfer))
        .route("/:transfer_id/ticket", post(issue_ticket))
        // Disable the default 2 MB JSON extractor cap; our transport-level
        // RequestBodyLimitLayer in build_app enforces the real ceiling.
        .layer(DefaultBodyLimit::disable())
}

// ---------- POST / ----------

#[derive(Debug, Deserialize)]
pub struct CreateTransferRequest {
    pub sender_agent_id: String,
    pub recipient: String,
    #[serde(default)]
    pub declared_mime: String,
    #[serde(default)]
    pub filename: String,
    pub nonce: String,
    pub issued_at: i64,
    pub intent_signature_hex: String,
    /// Hex-encoded payload (M1 path). Empty if tunnel_url is set.
    #[serde(default)]
    pub blob_hex: String,
    /// M2: URL of the sender's data plane (Cloudflare tunnel). When present,
    /// the control plane does NOT touch payload bytes; it only signs tickets.
    /// Mutually exclusive with blob_hex.
    #[serde(default)]
    pub tunnel_url: Option<String>,
    /// M2: sender-declared total size in bytes.
    #[serde(default)]
    pub declared_size: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct TransferResponse {
    pub transfer_id: String,
    pub state: String,
    pub sender_agent_id: String,
    pub recipient: String,
    pub size_bytes: u64,
    pub declared_mime: Option<String>,
    pub filename: Option<String>,
    pub scanner_verdict: Option<serde_json::Value>,
    pub policy_decision: Option<serde_json::Value>,
    pub rejection_code: Option<String>,
    pub rejection_reason: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

async fn create_transfer(
    State(state): State<AppState>,
    Json(req): Json<CreateTransferRequest>,
) -> Result<(StatusCode, Json<TransferResponse>), ApiError> {
    // Parse sender.
    let sender = AgentId::new(&req.sender_agent_id)?;
    let sender_row = agents_db::find_by_agent_id(&state.db, sender.as_str())
        .await?
        .ok_or_else(|| ApiError::Unauthorized("unknown sender".into()))?;

    // Validate shape.
    if req.recipient.is_empty() {
        return Err(ApiError::BadRequest("recipient is empty".into()));
    }
    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest("nonce length out of range".into()));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if !aex_core::wire::is_within_clock_skew(now, req.issued_at) {
        return Err(ApiError::BadRequest(
            "issued_at outside allowed skew".into(),
        ));
    }

    // ---- M2 branch: sender serves bytes via Cloudflare tunnel ----
    if let Some(tunnel_url) = req.tunnel_url.as_deref() {
        if !tunnel_url.starts_with("https://") {
            return Err(ApiError::BadRequest("tunnel_url must be https://".into()));
        }
        let declared_size = req.declared_size.ok_or_else(|| {
            ApiError::BadRequest("declared_size is required when tunnel_url is set".into())
        })?;
        if !req.blob_hex.is_empty() {
            return Err(ApiError::BadRequest(
                "blob_hex and tunnel_url are mutually exclusive".into(),
            ));
        }

        // Verify tunnel reachability from the control plane's perspective
        // BEFORE persisting the transfer. Without this check, a malicious
        // or misconfigured sender could announce a tunnel_url that does
        // not actually serve anything, leaving the recipient to fail at
        // ticket-fetch time. This is the HTTP-level half of the readiness
        // contract; the data-plane binary already did DNS+TCP on its own
        // end. Skippable via AEX_SKIP_TUNNEL_VALIDATION=1 for tests.
        if std::env::var("AEX_SKIP_TUNNEL_VALIDATION").ok().as_deref() != Some("1") {
            verify_tunnel_http_healthz(tunnel_url).await?;
        }

        // Verify sender intent signature — same canonical bytes as M1, just
        // without the blob present.
        let canonical = transfer_intent_bytes(
            sender.as_str(),
            &req.recipient,
            declared_size,
            &req.declared_mime,
            &req.filename,
            &req.nonce,
            req.issued_at,
        )
        .map_err(|e| ApiError::BadRequest(format!("cannot build intent: {}", e)))?;
        let sig_bytes = hex::decode(&req.intent_signature_hex)
            .map_err(|e| ApiError::BadRequest(format!("intent_signature_hex: {}", e)))?;
        if sig_bytes.len() != SIGNATURE_LEN {
            return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
        }
        let sender_pubkey_arr: [u8; 32] =
            sender_row.public_key.as_slice().try_into().map_err(|_| {
                ApiError::Internal(Box::new(crate::error::SimpleError(
                    "pubkey length".to_string(),
                )))
            })?;
        let sender_pubkey =
            ed25519_dalek::VerifyingKey::from_bytes(&sender_pubkey_arr).map_err(|e| {
                ApiError::Internal(Box::new(crate::error::SimpleError(format!(
                    "pubkey parse: {}",
                    e
                ))))
            })?;
        let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        use ed25519_dalek::Verifier;
        sender_pubkey
            .verify(&canonical, &sig)
            .map_err(|_| ApiError::Unauthorized("sender intent signature invalid".into()))?;

        // Consume intent nonce (replay protection).
        tx_db::consume_intent_nonce(&state.db, sender.as_str(), &req.nonce)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(d)
                    if d.constraint() == Some("transfer_intent_nonces_pkey") =>
                {
                    ApiError::Conflict("intent nonce already used".into())
                }
                other => ApiError::from(other),
            })?;

        let transfer_id = format!("tx_{}", hex::encode(rand::random::<[u8; 16]>()));
        let recipient_kind = classify_recipient(&req.recipient);

        let row = tx_db::insert(
            &state.db,
            tx_db::InsertTransfer {
                transfer_id: &transfer_id,
                sender_agent_id: sender.as_str(),
                recipient: &req.recipient,
                recipient_kind: recipient_kind_str(recipient_kind),
                state: "ready_for_pickup",
                size_bytes: declared_size as i64,
                declared_mime: opt_str(&req.declared_mime),
                filename: opt_str(&req.filename),
                blob_sha256: None,
                scanner_verdict: None,
                policy_decision: None,
                rejection_code: None,
                rejection_reason: None,
                tunnel_url: Some(tunnel_url),
            },
        )
        .await?;

        return Ok((StatusCode::CREATED, Json(row_to_response(row))));
    }
    // ---- End M2 branch. Fallback: M1 blob-hex flow. ----

    // Decode blob + signature.
    let blob =
        hex::decode(&req.blob_hex).map_err(|e| ApiError::BadRequest(format!("blob_hex: {}", e)))?;
    let sig_bytes = hex::decode(&req.intent_signature_hex)
        .map_err(|e| ApiError::BadRequest(format!("intent_signature_hex: {}", e)))?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
    }

    let size_bytes = blob.len() as u64;

    // Verify sender's intent signature.
    let canonical = transfer_intent_bytes(
        sender.as_str(),
        &req.recipient,
        size_bytes,
        &req.declared_mime,
        &req.filename,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("cannot build intent: {}", e)))?;

    let vk = verifying_key_from_pubkey_bytes(&sender_row.public_key)?;
    let dalek_sig: [u8; SIGNATURE_LEN] = sig_bytes.as_slice().try_into().expect("length checked");
    vk.verify(&canonical, &DalekSignature::from_bytes(&dalek_sig))
        .map_err(|_| ApiError::Unauthorized("intent signature invalid".into()))?;

    // Consume nonce (after signature passes, before DB side effects).
    let fresh = tx_db::consume_intent_nonce(&state.db, &req.nonce, sender.as_str()).await?;
    if !fresh {
        return Err(ApiError::Conflict("intent nonce already used".into()));
    }

    let transfer_id = format!("tx_{}", uuid::Uuid::new_v4().simple());
    let recipient_kind = classify_recipient(&req.recipient);

    // Audit: transfer initiated.
    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferInitiated,
            sender.as_str(),
            &transfer_id,
            json!({
                "recipient": &req.recipient,
                "recipient_kind": recipient_kind_str(recipient_kind),
                "size_bytes": size_bytes,
                "declared_mime": if req.declared_mime.is_empty() { None } else { Some(&req.declared_mime) },
                "filename": if req.filename.is_empty() { None } else { Some(&req.filename) },
            }),
        ),
    )
    .await;

    // Pre-scan policy.
    let pre_req = PolicyRequest::new(
        &sender,
        &sender_row.org,
        &req.recipient,
        recipient_kind,
        size_bytes,
    );
    let pre_req = if req.declared_mime.is_empty() {
        pre_req
    } else {
        pre_req.with_declared_mime(&req.declared_mime)
    };
    let pre_decision = state.policy.evaluate(&pre_req).await;
    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferPolicyDecision,
            sender.as_str(),
            &transfer_id,
            json!({"phase": "pre_scan", "decision": &pre_decision}),
        ),
    )
    .await;
    if let PolicyDecision::Deny { code, reason } = &pre_decision {
        let row = persist_rejected(
            &state,
            &transfer_id,
            &sender,
            &req,
            recipient_kind,
            size_bytes,
            None,
            Some(serde_json::to_value(&pre_decision).ok().unwrap_or_default()),
            code,
            reason,
        )
        .await?;
        return Ok((StatusCode::OK, Json(row_to_response(row))));
    }

    // Scanner.
    let scan_input = {
        let mut si = ScanInput::new(&blob);
        if !req.declared_mime.is_empty() {
            si = si.with_declared_mime(&req.declared_mime);
        }
        if !req.filename.is_empty() {
            si = si.with_filename(&req.filename);
        }
        si
    };
    let verdict = state.scanner.scan(&scan_input).await;
    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferScannerVerdict,
            sender.as_str(),
            &transfer_id,
            serde_json::to_value(&verdict).unwrap_or(serde_json::Value::Null),
        ),
    )
    .await;

    // Post-scan policy.
    let post_req = PolicyRequest {
        sender: &sender,
        sender_org: &sender_row.org,
        recipient: &req.recipient,
        recipient_kind,
        size_bytes,
        declared_mime: if req.declared_mime.is_empty() {
            None
        } else {
            Some(req.declared_mime.as_str())
        },
        scanner_verdict: Some(&verdict),
    };
    let post_decision = state.policy.evaluate(&post_req).await;
    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferPolicyDecision,
            sender.as_str(),
            &transfer_id,
            json!({"phase": "post_scan", "decision": &post_decision}),
        ),
    )
    .await;

    if let PolicyDecision::Deny { code, reason } = &post_decision {
        let row = persist_rejected(
            &state,
            &transfer_id,
            &sender,
            &req,
            recipient_kind,
            size_bytes,
            Some(&verdict),
            Some(
                serde_json::to_value(&post_decision)
                    .ok()
                    .unwrap_or_default(),
            ),
            code,
            reason,
        )
        .await?;
        return Ok((StatusCode::OK, Json(row_to_response(row))));
    }

    // Allow path: persist blob + transfer row.
    let blob_sha256 = hex::encode(Sha256::digest(&blob));
    state
        .blobs
        .put(&transfer_id, &blob)
        .await
        .map_err(ApiError::internal)?;

    let row = tx_db::insert(
        &state.db,
        tx_db::InsertTransfer {
            transfer_id: &transfer_id,
            sender_agent_id: sender.as_str(),
            recipient: &req.recipient,
            recipient_kind: recipient_kind_str(recipient_kind),
            state: "ready_for_pickup",
            size_bytes: size_bytes as i64,
            declared_mime: opt_str(&req.declared_mime),
            filename: opt_str(&req.filename),
            blob_sha256: Some(&blob_sha256),
            scanner_verdict: serde_json::to_value(&verdict).ok(),
            policy_decision: serde_json::to_value(&post_decision).ok(),
            rejection_code: None,
            rejection_reason: None,
            tunnel_url: None,
        },
    )
    .await?;

    Ok((StatusCode::CREATED, Json(row_to_response(row))))
}

async fn persist_rejected(
    state: &AppState,
    transfer_id: &str,
    sender: &AgentId,
    req: &CreateTransferRequest,
    recipient_kind: RecipientKind,
    size_bytes: u64,
    verdict: Option<&PipelineVerdict>,
    policy_decision: Option<serde_json::Value>,
    code: &str,
    reason: &str,
) -> Result<tx_db::TransferRow, ApiError> {
    let row = tx_db::insert(
        &state.db,
        tx_db::InsertTransfer {
            transfer_id,
            sender_agent_id: sender.as_str(),
            recipient: &req.recipient,
            recipient_kind: recipient_kind_str(recipient_kind),
            state: "rejected",
            size_bytes: size_bytes as i64,
            declared_mime: opt_str(&req.declared_mime),
            filename: opt_str(&req.filename),
            blob_sha256: None,
            scanner_verdict: verdict.and_then(|v| serde_json::to_value(v).ok()),
            policy_decision,
            rejection_code: Some(code),
            rejection_reason: Some(reason),
            tunnel_url: None,
        },
    )
    .await?;

    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferRejected,
            sender.as_str(),
            transfer_id,
            json!({"code": code, "reason": reason}),
        ),
    )
    .await;

    Ok(row)
}

// ---------- GET /:transfer_id ----------

async fn get_transfer(
    State(state): State<AppState>,
    Path(transfer_id): Path<String>,
) -> Result<Json<TransferResponse>, ApiError> {
    let row = tx_db::find_by_transfer_id(&state.db, &transfer_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("transfer {} not found", transfer_id)))?;
    Ok(Json(row_to_response(row)))
}

// ---------- POST /:transfer_id/download ----------

#[derive(Debug, Deserialize)]
pub struct RecipientReceiptRequest {
    pub recipient_agent_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct DownloadResponse {
    pub transfer_id: String,
    pub blob_hex: String,
    pub blob_sha256: String,
    pub filename: Option<String>,
    pub declared_mime: Option<String>,
}

async fn download_transfer(
    State(state): State<AppState>,
    Path(transfer_id): Path<String>,
    Json(req): Json<RecipientReceiptRequest>,
) -> Result<Json<DownloadResponse>, ApiError> {
    let row = verify_recipient_receipt(&state, &transfer_id, &req, "download").await?;
    if row.state == "rejected" {
        return Err(ApiError::NotFound("transfer was rejected".into()));
    }
    if !matches!(row.state.as_str(), "ready_for_pickup" | "accepted") {
        return Err(ApiError::Conflict(format!(
            "transfer is in state '{}', cannot download",
            row.state
        )));
    }

    let bytes = state
        .blobs
        .get(&transfer_id)
        .await
        .map_err(ApiError::internal)?;

    // Mark as accepted on first successful download (idempotent via state guard).
    tx_db::mark_accepted(&state.db, &transfer_id).await?;
    audit_warn(
        &state.audit,
        Event::new(
            EventKind::TransferAccepted,
            &req.recipient_agent_id,
            &transfer_id,
            json!({"nonce": &req.nonce}),
        ),
    )
    .await;

    Ok(Json(DownloadResponse {
        transfer_id: row.transfer_id,
        blob_hex: hex::encode(&bytes),
        blob_sha256: row.blob_sha256.unwrap_or_default(),
        filename: row.filename,
        declared_mime: row.declared_mime,
    }))
}

// ---------- POST /:transfer_id/ack ----------

#[derive(Debug, Serialize)]
pub struct AckResponse {
    pub transfer_id: String,
    pub state: String,
    pub audit_chain_head: String,
}

async fn ack_transfer(
    State(state): State<AppState>,
    Path(transfer_id): Path<String>,
    Json(req): Json<RecipientReceiptRequest>,
) -> Result<Json<AckResponse>, ApiError> {
    verify_recipient_receipt(&state, &transfer_id, &req, "ack").await?;

    let updated = tx_db::mark_delivered(&state.db, &transfer_id).await?;
    if updated == 0 {
        return Err(ApiError::Conflict(
            "transfer is not in a state that can be acked".into(),
        ));
    }
    let receipt = state
        .audit
        .append(Event::new(
            EventKind::TransferDelivered,
            &req.recipient_agent_id,
            &transfer_id,
            json!({"nonce": &req.nonce}),
        ))
        .await
        .map_err(ApiError::internal)?;

    // Blob is no longer needed — free the temp copy.
    let _ = state.blobs.delete(&transfer_id).await;

    Ok(Json(AckResponse {
        transfer_id,
        state: "delivered".into(),
        audit_chain_head: receipt.chain_head,
    }))
}

async fn verify_recipient_receipt(
    state: &AppState,
    transfer_id: &str,
    req: &RecipientReceiptRequest,
    action: &str,
) -> Result<tx_db::TransferRow, ApiError> {
    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest("nonce length out of range".into()));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if !aex_core::wire::is_within_clock_skew(now, req.issued_at) {
        return Err(ApiError::BadRequest(
            "issued_at outside allowed skew".into(),
        ));
    }

    let recipient = AgentId::new(&req.recipient_agent_id)?;
    let row = tx_db::find_by_transfer_id(&state.db, transfer_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("transfer {} not found", transfer_id)))?;
    if row.recipient != recipient.as_str() {
        return Err(ApiError::Unauthorized("you are not the recipient".into()));
    }

    let rec_row = agents_db::find_by_agent_id(&state.db, recipient.as_str())
        .await?
        .ok_or_else(|| ApiError::Unauthorized("recipient agent not registered".into()))?;

    let canonical = transfer_receipt_bytes(
        recipient.as_str(),
        transfer_id,
        action,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("canonical: {}", e)))?;

    let vk = verifying_key_from_pubkey_bytes(&rec_row.public_key)?;
    let sig_bytes = hex::decode(&req.signature_hex)
        .map_err(|e| ApiError::BadRequest(format!("signature_hex: {}", e)))?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
    }
    let sig_arr: [u8; SIGNATURE_LEN] = sig_bytes.as_slice().try_into().unwrap();
    vk.verify(&canonical, &DalekSignature::from_bytes(&sig_arr))
        .map_err(|_| ApiError::Unauthorized("receipt signature invalid".into()))?;

    Ok(row)
}

// ---------- helpers ----------

fn verifying_key_from_pubkey_bytes(bytes: &[u8]) -> Result<VerifyingKey, ApiError> {
    let arr: [u8; PUBLIC_KEY_LEN] = bytes.try_into().map_err(|_| {
        ApiError::internal(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad pubkey length in database",
        ))
    })?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| ApiError::internal(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

fn classify_recipient(recipient: &str) -> RecipientKind {
    if recipient.starts_with("spize:") {
        RecipientKind::SpizeNative
    } else if recipient.starts_with("did:") {
        RecipientKind::Did
    } else if recipient.contains('@') || recipient.starts_with('+') {
        RecipientKind::HumanBridge
    } else {
        RecipientKind::Unknown
    }
}

fn recipient_kind_str(k: RecipientKind) -> &'static str {
    match k {
        RecipientKind::SpizeNative => "spize_native",
        RecipientKind::Did => "did",
        RecipientKind::HumanBridge => "human_bridge",
        RecipientKind::Unknown => "unknown",
    }
}

fn opt_str(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn row_to_response(row: tx_db::TransferRow) -> TransferResponse {
    TransferResponse {
        transfer_id: row.transfer_id,
        state: row.state,
        sender_agent_id: row.sender_agent_id,
        recipient: row.recipient,
        size_bytes: row.size_bytes as u64,
        declared_mime: row.declared_mime,
        filename: row.filename,
        scanner_verdict: row.scanner_verdict,
        policy_decision: row.policy_decision,
        rejection_code: row.rejection_code,
        rejection_reason: row.rejection_reason,
        created_at: row.created_at,
    }
}

// ============================================================================
// M2: data-plane ticket issuance
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct TicketRequest {
    pub recipient_agent_id: String,
    pub nonce: String,
    pub issued_at: i64,
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct TicketResponse {
    pub transfer_id: String,
    pub recipient: String,
    pub data_plane_url: String,
    pub expires: i64,
    pub nonce: String,
    pub signature: String,
}

const TICKET_ACTION: &str = "request_ticket";
const TICKET_TTL_SECONDS: i64 = 60;

pub async fn issue_ticket(
    State(state): State<AppState>,
    Path(transfer_id): Path<String>,
    Json(req): Json<TicketRequest>,
) -> Result<Json<TicketResponse>, ApiError> {
    let signer = state.signer.as_ref().ok_or_else(|| {
        ApiError::Internal(Box::new(crate::error::SimpleError(
            "control plane signing key is not configured".to_string(),
        )))
    })?;

    let recipient = AgentId::new(&req.recipient_agent_id)?;

    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest("nonce length out of range".into()));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if !aex_core::wire::is_within_clock_skew(now, req.issued_at) {
        return Err(ApiError::BadRequest(
            "issued_at outside allowed skew".into(),
        ));
    }

    let row = tx_db::find_by_transfer_id(&state.db, &transfer_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("unknown transfer: {}", transfer_id)))?;
    if row.recipient != *recipient.as_str() {
        return Err(ApiError::Unauthorized(
            "recipient does not match transfer".into(),
        ));
    }
    if row.state != "ready_for_pickup" {
        return Err(ApiError::BadRequest(format!(
            "transfer is in state '{}', not ready_for_pickup",
            row.state
        )));
    }
    let tunnel_url = row
        .tunnel_url
        .clone()
        .ok_or_else(|| ApiError::BadRequest("transfer has no data-plane tunnel URL".into()))?;

    let receipt_canonical = aex_core::wire::transfer_receipt_bytes(
        recipient.as_str(),
        &transfer_id,
        TICKET_ACTION,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("canonicalisation: {}", e)))?;

    let sig_bytes = hex::decode(&req.signature_hex)
        .map_err(|e| ApiError::BadRequest(format!("receipt_signature_hex: {}", e)))?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
    }

    let rec_row = agents_db::find_by_agent_id(&state.db, recipient.as_str())
        .await?
        .ok_or_else(|| ApiError::Unauthorized("recipient not registered".into()))?;

    let pubkey_arr: [u8; 32] = rec_row.public_key.as_slice().try_into().map_err(|_| {
        ApiError::Internal(Box::new(crate::error::SimpleError(
            "pubkey length".to_string(),
        )))
    })?;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| {
        ApiError::Internal(Box::new(crate::error::SimpleError(format!(
            "pubkey parse: {}",
            e
        ))))
    })?;
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    use ed25519_dalek::Verifier;
    pubkey
        .verify(&receipt_canonical, &sig)
        .map_err(|_| ApiError::Unauthorized("recipient signature does not verify".into()))?;

    let expires = now + TICKET_TTL_SECONDS;
    let ticket_nonce = hex::encode(rand::random::<[u8; 16]>());
    let canon = aex_core::wire::data_ticket_bytes(
        &transfer_id,
        recipient.as_str(),
        &tunnel_url,
        expires,
        &ticket_nonce,
    )
    .map_err(|e| {
        ApiError::Internal(Box::new(crate::error::SimpleError(format!(
            "canonicalisation: {}",
            e
        ))))
    })?;

    let ticket_sig = signer.sign(&canon);

    sqlx::query(
        "INSERT INTO data_plane_ticket_nonces (nonce, transfer_id, expires_at)          VALUES ($1, $2, to_timestamp($3))",
    )
    .bind(&ticket_nonce)
    .bind(&transfer_id)
    .bind(expires as f64)
    .execute(&state.db)
    .await
    .map_err(ApiError::from)?;

    Ok(Json(TicketResponse {
        transfer_id,
        recipient: recipient.to_string(),
        data_plane_url: tunnel_url,
        expires,
        nonce: ticket_nonce,
        signature: hex::encode(&ticket_sig),
    }))
}

/// HTTP-level healthcheck of the sender's tunnel_url. Runs during
/// `create_transfer` on the M2 branch — before we persist the transfer,
/// before we consume the intent nonce, before we hand the recipient a
/// ticket pointing at a URL that doesn't serve anything.
///
/// Three attempts with 3s spacing. Total worst case ~40s (3 × 10s
/// request timeout + 2 × 3s sleep). The control plane is on a
/// different host than the sender's data plane, so this is a clean
/// "client→edge→tunnel→target" path with none of the same-host loop
/// complications that affect a binary trying to GET its own URL.
async fn verify_tunnel_http_healthz(tunnel_url: &str) -> Result<(), ApiError> {
    let healthz = format!("{}/healthz", tunnel_url.trim_end_matches('/'));
    // The AEX DoH resolver + TLS + user-agent are supplied by `aex-net`.
    // See `aex_net::build_http_client_with_timeout` for the full rationale;
    // the short version is that reqwest's built-in hickory integration
    // reads `/etc/resolv.conf`, which on laptops often contains a local
    // search suffix (e.g. the wifi name) that corrupts lookups of public
    // hostnames into `host.suffix.`.
    let client = aex_net::build_http_client_with_timeout(
        "control-plane",
        std::time::Duration::from_secs(10),
    )
    .map_err(|e| {
        ApiError::Internal(Box::new(crate::error::SimpleError(format!(
            "aex-net http client build: {e}"
        ))))
    })?;

    // Widen retry budget: a Cloudflare quick-tunnel may answer DNS+TCP
    // a few seconds before its HTTP layer is fully wired, especially
    // when we're hitting it mere seconds after `AEX_READY=1`.
    let max_attempts: u32 = 6;
    let mut last_err = String::new();
    for attempt in 1..=max_attempts {
        match client.get(&healthz).send().await {
            Ok(r) if r.status().is_success() => {
                tracing::debug!(attempt, %healthz, "tunnel healthz OK");
                return Ok(());
            }
            Ok(r) => {
                last_err = format!("status {}", r.status());
            }
            Err(e) => {
                // reqwest's Display on an Error hides the source; walk
                // the chain so the user gets a real diagnostic when
                // the check fails.
                last_err = format_error_chain(&e);
            }
        }
        tracing::debug!(attempt, err = %last_err, "tunnel healthz not ready");
        if attempt < max_attempts {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    Err(ApiError::BadRequest(format!(
        "tunnel_url {tunnel_url} did not respond 200 on /healthz after {max_attempts} attempts (last: {last_err}). \
         Ensure the data plane is running and AEX_READY=1 has been emitted before calling send_via_tunnel."
    )))
}

fn format_error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut out = err.to_string();
    let mut current = err.source();
    while let Some(src) = current {
        out.push_str(" -> ");
        out.push_str(&src.to_string());
        current = src.source();
    }
    out
}
