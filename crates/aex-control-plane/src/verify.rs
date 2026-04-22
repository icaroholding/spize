//! Signature-verification helpers that honour the 24h rotation grace
//! window (ADR-0024).
//!
//! Every signed recipient / sender action (download, ack, inbox,
//! request_ticket, transfer intent) must accept a signature made by
//! ANY key valid for the agent at the moment the control plane
//! evaluates the request. Reading a single `public_key` off the
//! `agents` row would silently drop signatures from keys still inside
//! their grace window — the whole point of the rotation protocol is to
//! keep those working for 24h.

use ed25519_dalek::{Signature as DalekSignature, Verifier, VerifyingKey};
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::db::agent_keys as keys_db;
use crate::error::ApiError;

const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// Try to verify `signature` against `canonical` using every key that
/// is valid for `agent_id` at `at`. Returns `Ok(())` on the first
/// match; `Err(ApiError::Unauthorized)` if no candidate key verifies.
///
/// The lookup hits the `idx_agent_keys_valid_to` index so the hot
/// path stays cheap even after years of rotations accumulate.
pub async fn verify_with_valid_keys(
    pool: &PgPool,
    agent_id: &str,
    at: OffsetDateTime,
    canonical: &[u8],
    signature: &[u8],
) -> Result<(), ApiError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(ApiError::BadRequest("signature must be 64 bytes".into()));
    }
    let sig_arr: [u8; SIGNATURE_LEN] = signature.try_into().expect("length already validated");
    let dalek_sig = DalekSignature::from_bytes(&sig_arr);

    let candidates = keys_db::valid_public_keys_at(pool, agent_id, at).await?;
    if candidates.is_empty() {
        return Err(ApiError::Unauthorized(
            "no active key for agent (unregistered or revoked)".into(),
        ));
    }

    for pk in &candidates {
        let Ok(pk_arr) = <[u8; PUBLIC_KEY_LEN]>::try_from(pk.as_slice()) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
            continue;
        };
        if vk.verify(canonical, &dalek_sig).is_ok() {
            return Ok(());
        }
    }

    Err(ApiError::Unauthorized(
        "signature does not verify against any active key".into(),
    ))
}
