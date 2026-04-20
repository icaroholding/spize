//! Data-plane ticket — signed capability authorising a recipient to
//! fetch a specific transfer from this data plane.

use std::collections::HashSet;
use std::sync::Mutex;

use aex_core::wire::data_ticket_bytes;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TicketError {
    #[error("invalid base64/hex: {0}")]
    Encoding(String),

    #[error("invalid signature")]
    BadSignature,

    #[error("ticket expired at {expires}, now {now}")]
    Expired { expires: i64, now: i64 },

    #[error("ticket not for this data plane (ticket says {ticket}, we are {ours})")]
    WrongAudience { ticket: String, ours: String },

    #[error("nonce already used")]
    NonceReplay,

    #[error("canonicalisation: {0}")]
    Canon(String),
}

/// A ticket as it travels over the wire (JSON body of the X-AEX-Ticket header).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ticket {
    pub transfer_id: String,
    pub recipient: String,
    pub data_plane_url: String,
    pub expires: i64,
    pub nonce: String,
    pub signature: String, // hex-encoded Ed25519
}

#[derive(Debug, Clone)]
pub struct VerifiedTicket {
    pub transfer_id: String,
    pub recipient: String,
    pub expires: i64,
    pub nonce: String,
}

pub struct TicketVerifier {
    control_plane_pubkey: VerifyingKey,
    data_plane_url: String,
    skew_seconds: i64,
    used_nonces: Mutex<HashSet<String>>,
}

impl TicketVerifier {
    pub fn new(control_plane_pubkey: VerifyingKey, data_plane_url: impl Into<String>) -> Self {
        Self {
            control_plane_pubkey,
            data_plane_url: data_plane_url.into(),
            skew_seconds: 60,
            used_nonces: Mutex::new(HashSet::new()),
        }
    }

    pub fn with_skew(mut self, skew_seconds: i64) -> Self {
        self.skew_seconds = skew_seconds;
        self
    }

    pub fn verify(&self, ticket: &Ticket) -> Result<VerifiedTicket, TicketError> {
        if ticket.data_plane_url != self.data_plane_url {
            return Err(TicketError::WrongAudience {
                ticket: ticket.data_plane_url.clone(),
                ours: self.data_plane_url.clone(),
            });
        }

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        if ticket.expires + self.skew_seconds < now {
            return Err(TicketError::Expired {
                expires: ticket.expires,
                now,
            });
        }

        let sig_bytes = hex::decode(&ticket.signature)
            .map_err(|e| TicketError::Encoding(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TicketError::Encoding("signature not 64 bytes".to_string()))?;
        let sig = Signature::from_bytes(&sig_arr);

        let canon = data_ticket_bytes(
            &ticket.transfer_id,
            &ticket.recipient,
            &ticket.data_plane_url,
            ticket.expires,
            &ticket.nonce,
        )
        .map_err(|e| TicketError::Canon(e.to_string()))?;

        self.control_plane_pubkey
            .verify(&canon, &sig)
            .map_err(|_| TicketError::BadSignature)?;

        let mut used = self.used_nonces.lock().expect("nonces lock");
        if !used.insert(ticket.nonce.clone()) {
            return Err(TicketError::NonceReplay);
        }

        Ok(VerifiedTicket {
            transfer_id: ticket.transfer_id.clone(),
            recipient: ticket.recipient.clone(),
            expires: ticket.expires,
            nonce: ticket.nonce.clone(),
        })
    }
}
