//! Agents HTTP endpoints.
//!
//! **POST /v1/agents/register** — the core registration flow. The client:
//!   1. Generates an Ed25519 keypair locally.
//!   2. Builds the canonical challenge via
//!      [`aex_core::wire::registration_challenge_bytes`].
//!   3. Signs it with the private key.
//!   4. Submits `{public_key_hex, org, name, nonce, issued_at, signature_hex}`.
//!
//! The server re-derives the challenge bytes, verifies the signature against
//! the submitted public key, enforces timestamp freshness and nonce single-
//! use, computes the canonical `agent_id`, and persists. Private keys never
//! leave the client device — the server only stores the public half.
//!
//! **GET /v1/agents/:agent_id** — resolve an agent_id to its public key. Used
//! by peers during transfer to verify signed messages.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use aex_core::wire::{
    registration_challenge_bytes, rotate_key_challenge_bytes, MAX_CLOCK_SKEW_SECS, MAX_NONCE_LEN,
    MIN_NONCE_LEN,
};

use crate::{
    db::{agent_keys as keys_db, agents as db},
    error::ApiError,
    AppState,
};

const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const MAX_LABEL_LEN: usize = 64;

pub fn router() -> Router<AppState> {
    // Wildcard `*agent_id` captures the rest of the path including slashes,
    // because agent_ids contain `/` (e.g. `spize:acme/alice:a4f8b2`). Axum
    // resolves `/register` with higher specificity than the wildcard, so
    // route order does not matter. Inbox lives at its own top-level
    // `POST /v1/inbox` (see routes::inbox) to avoid wildcard ambiguity.
    Router::new()
        .route("/register", post(register))
        .route("/rotate-key", post(rotate_key))
        .route("/*agent_id", get(get_agent))
}

// ---------- POST /register ----------

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    /// Hex-encoded Ed25519 public key (32 bytes → 64 hex chars).
    pub public_key_hex: String,
    pub org: String,
    pub name: String,
    /// Hex, 32–128 chars, client-generated.
    pub nonce: String,
    /// Unix seconds at which the client built the challenge.
    pub issued_at: i64,
    /// Hex-encoded Ed25519 signature (64 bytes → 128 hex chars) over the
    /// canonical challenge bytes.
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct AgentResponse {
    pub agent_id: String,
    pub public_key_hex: String,
    pub fingerprint: String,
    pub org: String,
    pub name: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AgentResponse>), ApiError> {
    // 1. Shape validation.
    validate_label(&req.org, "org")?;
    validate_label(&req.name, "name")?;
    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest(format!(
            "nonce length must be {}..={} hex chars",
            MIN_NONCE_LEN, MAX_NONCE_LEN
        )));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }

    let public_key = decode_hex_exact(&req.public_key_hex, PUBLIC_KEY_LEN, "public_key_hex")?;
    let signature = decode_hex_exact(&req.signature_hex, SIGNATURE_LEN, "signature_hex")?;

    // 2. Freshness. Overflow-safe even on adversarial timestamps.
    let now_unix = state.clock.now_unix();
    if !aex_core::wire::is_within_clock_skew(now_unix, req.issued_at) {
        return Err(ApiError::BadRequest(format!(
            "issued_at is outside allowed skew (±{}s)",
            MAX_CLOCK_SKEW_SECS
        )));
    }

    // 3. Cryptographic verification.
    let challenge = registration_challenge_bytes(
        &req.public_key_hex,
        &req.org,
        &req.name,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("cannot build challenge: {}", e)))?;

    let vk_bytes: [u8; PUBLIC_KEY_LEN] = public_key
        .as_slice()
        .try_into()
        .expect("length already validated");
    let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid public key: {}", e)))?;

    let sig_bytes: [u8; SIGNATURE_LEN] = signature
        .as_slice()
        .try_into()
        .expect("length already validated");
    let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&challenge, &dalek_sig)
        .map_err(|_| ApiError::Unauthorized("signature does not match challenge".into()))?;

    // 4. Nonce single-use (replay protection). Must come AFTER signature
    //    verification to avoid letting unauthenticated traffic fill the
    //    nonce table.
    let fresh = db::consume_nonce(&state.db, &req.nonce, &public_key).await?;
    if !fresh {
        return Err(ApiError::Conflict("nonce already used".into()));
    }

    // 5. Derive canonical agent_id server-side.
    let fingerprint = compute_fingerprint(&public_key);
    let agent_id = format!("spize:{}/{}:{}", req.org, req.name, fingerprint);

    // 6. Persist.
    match db::insert(
        &state.db,
        &agent_id,
        &public_key,
        &fingerprint,
        &req.org,
        &req.name,
    )
    .await
    {
        Ok(row) => Ok((
            StatusCode::CREATED,
            Json(AgentResponse {
                agent_id: row.agent_id,
                public_key_hex: hex::encode(&row.public_key),
                fingerprint: row.fingerprint,
                org: row.org,
                name: row.name,
                created_at: row.created_at,
            }),
        )),
        Err(err) => {
            if let Some(field) = db::unique_violation_field(&err) {
                Err(ApiError::Conflict(format!("{} already registered", field)))
            } else {
                Err(err.into())
            }
        }
    }
}

// ---------- GET /:agent_id ----------

async fn get_agent(
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<AgentResponse>, ApiError> {
    // Parse through AgentId to reject malformed lookups early.
    let parsed = aex_core::AgentId::new(&agent_id)?;

    let row = db::find_by_agent_id(&state.db, parsed.as_str())
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("agent {} not found", parsed)))?;

    Ok(Json(AgentResponse {
        agent_id: row.agent_id,
        public_key_hex: hex::encode(&row.public_key),
        fingerprint: row.fingerprint,
        org: row.org,
        name: row.name,
        created_at: row.created_at,
    }))
}

// ---------- POST /rotate-key ----------

#[derive(Debug, Deserialize)]
pub struct RotateKeyRequest {
    /// Canonical agent_id whose key is rotating.
    pub agent_id: String,
    /// Hex-encoded NEW Ed25519 public key (32 bytes → 64 hex chars).
    pub new_public_key_hex: String,
    /// Hex, 32–128 chars, client-generated.
    pub nonce: String,
    /// Unix seconds at which the client built the challenge.
    pub issued_at: i64,
    /// Signature (hex, 128 chars) over the canonical
    /// `rotate_key_challenge_bytes` made with the CURRENT (outgoing) key.
    pub signature_hex: String,
}

#[derive(Debug, Serialize)]
pub struct RotateKeyResponse {
    pub agent_id: String,
    pub new_public_key_hex: String,
    /// Unix seconds at which the new key became the current key.
    pub valid_from: i64,
    /// Unix seconds at which the previous key stops verifying. Clients
    /// should treat any signature older than this from the old key as
    /// still valid; signatures produced after this must use the new key.
    pub previous_key_valid_until: i64,
}

async fn rotate_key(
    State(state): State<AppState>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<(StatusCode, Json<RotateKeyResponse>), ApiError> {
    // 1. Shape validation.
    let agent = aex_core::AgentId::new(&req.agent_id)?;

    if req.nonce.len() < MIN_NONCE_LEN || req.nonce.len() > MAX_NONCE_LEN {
        return Err(ApiError::BadRequest(format!(
            "nonce length must be {}..={} hex chars",
            MIN_NONCE_LEN, MAX_NONCE_LEN
        )));
    }
    if !req.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(ApiError::BadRequest("nonce must be hex".into()));
    }

    let new_public_key = decode_hex_exact(
        &req.new_public_key_hex,
        PUBLIC_KEY_LEN,
        "new_public_key_hex",
    )?;
    let signature = decode_hex_exact(&req.signature_hex, SIGNATURE_LEN, "signature_hex")?;

    // 2. Freshness. Clock injected so tests can cross the grace boundary.
    let now_unix = state.clock.now_unix();
    if !aex_core::wire::is_within_clock_skew(now_unix, req.issued_at) {
        return Err(ApiError::BadRequest(format!(
            "issued_at is outside allowed skew (±{}s)",
            MAX_CLOCK_SKEW_SECS
        )));
    }

    // 3. Resolve the CURRENT key for the agent. Rotation MUST be
    //    authorised by the current key, not a key still inside its
    //    grace window — grace is for receivers, not senders.
    let current = keys_db::current_key(&state.db, agent.as_str())
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("agent {} not found", agent)))?;

    // 4. Reject trivial rotations: the "new" key must differ from the
    //    current one. Otherwise a buggy client could churn the
    //    rotation history with duplicate rows.
    if current.public_key_hex == req.new_public_key_hex {
        return Err(ApiError::BadRequest(
            "new_public_key_hex must differ from the current key".into(),
        ));
    }

    // 5. Cryptographic verification against the current key.
    let challenge = rotate_key_challenge_bytes(
        agent.as_str(),
        &current.public_key_hex,
        &req.new_public_key_hex,
        &req.nonce,
        req.issued_at,
    )
    .map_err(|e| ApiError::BadRequest(format!("cannot build challenge: {}", e)))?;

    let vk_bytes: [u8; PUBLIC_KEY_LEN] =
        current.public_key.as_slice().try_into().map_err(|_| {
            ApiError::internal(std::io::Error::other("bad stored public_key length"))
        })?;
    let verifying_key = VerifyingKey::from_bytes(&vk_bytes)
        .map_err(|e| ApiError::internal(std::io::Error::other(e)))?;

    let sig_bytes: [u8; SIGNATURE_LEN] = signature
        .as_slice()
        .try_into()
        .expect("length already validated");
    let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&challenge, &dalek_sig)
        .map_err(|_| ApiError::Unauthorized("signature does not match challenge".into()))?;

    // 6. Validate the new key parses as a real Ed25519 VerifyingKey
    //    BEFORE persisting. Saves us from ending up with a "current"
    //    key that no future call can ever verify against.
    let new_vk_bytes: [u8; PUBLIC_KEY_LEN] = new_public_key
        .as_slice()
        .try_into()
        .expect("length already validated");
    VerifyingKey::from_bytes(&new_vk_bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid new public key: {}", e)))?;

    // 7. Nonce single-use (replay protection). AFTER signature check
    //    so unauthenticated noise can't fill the table.
    let fresh = keys_db::consume_rotate_nonce(&state.db, &req.nonce, agent.as_str()).await?;
    if !fresh {
        return Err(ApiError::Conflict("nonce already used".into()));
    }

    // 8. Persist atomically. Pass the current public_key_hex we just
    //    verified against so the UPDATE fails cleanly if a concurrent
    //    rotate-key call has already moved the active key off it.
    let now = state.clock.now();
    let row = match keys_db::insert_rotation(
        &state.db,
        agent.as_str(),
        &current.public_key_hex,
        &req.new_public_key_hex,
        &new_public_key,
        now,
    )
    .await
    {
        Ok(row) => row,
        Err(sqlx::Error::RowNotFound) => {
            // Concurrent rotation beat us to the active row.
            return Err(ApiError::Conflict(
                "agent key rotated concurrently; retry with the new current key".into(),
            ));
        }
        Err(err) => {
            if let Some(field) = keys_db::unique_violation_field(&err) {
                return Err(ApiError::Conflict(format!(
                    "rotation conflict ({}): another rotation to this key already exists",
                    field
                )));
            }
            return Err(err.into());
        }
    };

    let previous_key_valid_until = now.unix_timestamp() + keys_db::ROTATION_GRACE_SECS;

    Ok((
        StatusCode::OK,
        Json(RotateKeyResponse {
            agent_id: row.agent_id,
            new_public_key_hex: row.public_key_hex,
            valid_from: row.valid_from.unix_timestamp(),
            previous_key_valid_until,
        }),
    ))
}

// ---------- helpers ----------

fn validate_label(s: &str, field: &str) -> Result<(), ApiError> {
    if s.is_empty() {
        return Err(ApiError::BadRequest(format!("{} is empty", field)));
    }
    if s.len() > MAX_LABEL_LEN {
        return Err(ApiError::BadRequest(format!(
            "{} exceeds {} chars",
            field, MAX_LABEL_LEN
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(ApiError::BadRequest(format!(
            "{} must match [a-zA-Z0-9_-]+",
            field
        )));
    }
    Ok(())
}

fn decode_hex_exact(s: &str, expected: usize, field: &str) -> Result<Vec<u8>, ApiError> {
    let bytes = hex::decode(s)
        .map_err(|e| ApiError::BadRequest(format!("{}: invalid hex ({})", field, e)))?;
    if bytes.len() != expected {
        return Err(ApiError::BadRequest(format!(
            "{}: expected {} bytes, got {}",
            field,
            expected,
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn compute_fingerprint(public_key: &[u8]) -> String {
    let hash = Sha256::digest(public_key);
    hex::encode(&hash[..3])
}
