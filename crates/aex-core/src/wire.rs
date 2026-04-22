//! On-the-wire formats shared between SDKs and the control plane.
//!
//! This module intentionally defines plain byte formats rather than JSON
//! envelopes. Canonical byte sequences are the source of truth for what
//! gets signed — any framing (JSON, protobuf, HTTP headers) is a transport
//! concern and must not alter the signed bytes.

use crate::{Error, Result};

/// Current wire protocol version. Bumped only when the canonical byte
/// sequence of any message format below changes. Old versions must continue
/// to verify for audit replay.
pub const PROTOCOL_VERSION: &str = "v1";

/// Maximum acceptable clock skew between client and server, in seconds.
/// Messages older/newer than this are rejected to limit replay windows.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Check if `issued_at` is within the allowed skew relative to `now`.
/// Overflow-safe: a malicious client sending `i64::MIN` or `i64::MAX`
/// cannot panic the server (release-mode wraparound would previously
/// silently accept those values; debug-mode would panic).
///
/// Returns `true` if the message is fresh enough.
pub fn is_within_clock_skew(now_unix: i64, issued_at_unix: i64) -> bool {
    let diff = (now_unix as i128).saturating_sub(issued_at_unix as i128);
    diff.unsigned_abs() <= MAX_CLOCK_SKEW_SECS as u128
}

/// Minimum nonce length (hex chars). 32 chars = 128 bits of entropy.
pub const MIN_NONCE_LEN: usize = 32;

/// Maximum nonce length (hex chars). Prevents pathological inputs.
pub const MAX_NONCE_LEN: usize = 128;

/// Produce the canonical bytes that a client signs to prove possession of
/// the private key matching `public_key_hex` when registering an agent.
///
/// Format (line-based, LF terminator on each line, no trailing LF on the
/// last line):
///
/// ```text
/// spize-register:v1
/// pub={public_key_hex}
/// org={org}
/// name={name}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
///
/// All inputs must be ASCII. The function validates inputs and returns an
/// error if any field contains characters that could allow canonicalization
/// ambiguity (newlines, NULs, non-ASCII).
pub fn registration_challenge_bytes(
    public_key_hex: &str,
    org: &str,
    name: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(public_key_hex, "public_key_hex")?;
    validate_ascii_line(org, "org")?;
    validate_ascii_line(name, "name")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "spize-register:{version}\npub={pub}\norg={org}\nname={name}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION,
        pub = public_key_hex,
        org = org,
        name = name,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Ensure a string is safe to embed in a single-line canonical field.
fn validate_ascii_line(s: &str, field: &str) -> Result<()> {
    if s.is_empty() {
        return Err(Error::Internal(format!("{} is empty", field)));
    }
    for (i, c) in s.chars().enumerate() {
        if !c.is_ascii() || c == '\n' || c == '\r' || c == '\0' {
            return Err(Error::Internal(format!(
                "{} has invalid char at {}: {:?}",
                field, i, c
            )));
        }
    }
    Ok(())
}

/// Allow-empty variant — used for optional fields (filename, declared_mime).
fn validate_ascii_line_opt(s: &str, field: &str) -> Result<()> {
    if s.is_empty() {
        return Ok(());
    }
    validate_ascii_line(s, field)
}

/// Canonical bytes signed by the **sender** when initiating a transfer.
///
/// Format:
/// ```text
/// spize-transfer-intent:v1
/// sender={sender_agent_id}
/// recipient={recipient}
/// size={size_bytes}
/// mime={declared_mime_or_empty}
/// filename={filename_or_empty}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
pub fn transfer_intent_bytes(
    sender_agent_id: &str,
    recipient: &str,
    size_bytes: u64,
    declared_mime: &str,
    filename: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(sender_agent_id, "sender_agent_id")?;
    validate_ascii_line(recipient, "recipient")?;
    validate_ascii_line_opt(declared_mime, "declared_mime")?;
    validate_ascii_line_opt(filename, "filename")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "spize-transfer-intent:{version}\nsender={sender}\nrecipient={recipient}\nsize={size}\nmime={mime}\nfilename={filename}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION,
        sender = sender_agent_id,
        recipient = recipient,
        size = size_bytes,
        mime = declared_mime,
        filename = filename,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by the **control plane** when issuing a data-
/// plane ticket. A ticket is a short-lived capability that authorises
/// the holder to fetch blob bytes from a data-plane server directly,
/// without the control plane proxying the stream.
///
/// Data-plane servers verify the ticket signature against the control
/// plane's published public key (fetched from `/.well-known/spize-cp.pub`
/// or out-of-band) before streaming bytes.
///
/// ```text
/// spize-data-ticket:v1
/// transfer={transfer_id}
/// recipient={recipient_agent_id}
/// data_plane={data_plane_url}
/// expires={expires_unix}
/// nonce={nonce}
/// ```
pub fn data_ticket_bytes(
    transfer_id: &str,
    recipient_agent_id: &str,
    data_plane_url: &str,
    expires_unix: i64,
    nonce: &str,
) -> Result<Vec<u8>> {
    validate_ascii_line(transfer_id, "transfer_id")?;
    validate_ascii_line(recipient_agent_id, "recipient_agent_id")?;
    validate_ascii_line(data_plane_url, "data_plane_url")?;
    validate_nonce(nonce)?;

    let msg = format!(
        "spize-data-ticket:{version}\ntransfer={tx}\nrecipient={rec}\ndata_plane={dp}\nexpires={exp}\nnonce={nonce}",
        version = PROTOCOL_VERSION,
        tx = transfer_id,
        rec = recipient_agent_id,
        dp = data_plane_url,
        exp = expires_unix,
        nonce = nonce,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by an agent's **outgoing** (current) key when
/// requesting to rotate to a new public key. Part of the formal rotation
/// protocol defined in ADR-0024.
///
/// The control plane re-derives these bytes and verifies the signature
/// against the CURRENT stored public key for `agent_id`. On success it
/// records the new key with `valid_from = now()` and closes the old
/// key's `valid_to` window 24h in the future — during that grace period
/// signatures from either key verify, so in-flight receipts signed by
/// the old key keep working while new signatures use the new one.
///
/// The new key is declared but NOT required to co-sign: the current key
/// authorises, and the agent is trusted to have proof-of-possession of
/// the new key through the device-local generation path. This mirrors
/// ADR-0024's "old key authorises, new key takes over after grace".
///
/// Format:
/// ```text
/// spize-rotate-key:v1
/// agent={agent_id}
/// old_pub={current_public_key_hex}
/// new_pub={new_public_key_hex}
/// nonce={nonce}
/// ts={issued_at_unix}
/// ```
pub fn rotate_key_challenge_bytes(
    agent_id: &str,
    old_public_key_hex: &str,
    new_public_key_hex: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(agent_id, "agent_id")?;
    validate_ascii_line(old_public_key_hex, "old_public_key_hex")?;
    validate_ascii_line(new_public_key_hex, "new_public_key_hex")?;
    validate_nonce(nonce)?;

    if old_public_key_hex == new_public_key_hex {
        return Err(Error::Internal(
            "old_public_key_hex and new_public_key_hex must differ".into(),
        ));
    }

    let msg = format!(
        "spize-rotate-key:{version}\nagent={agent}\nold_pub={old}\nnew_pub={new}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION,
        agent = agent_id,
        old = old_public_key_hex,
        new = new_public_key_hex,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

/// Canonical bytes signed by the **recipient** when requesting the blob or
/// acknowledging delivery. Binds the recipient's identity to the specific
/// transfer_id and a fresh nonce to prevent replay.
pub fn transfer_receipt_bytes(
    recipient_agent_id: &str,
    transfer_id: &str,
    action: &str,
    nonce: &str,
    issued_at_unix: i64,
) -> Result<Vec<u8>> {
    validate_ascii_line(recipient_agent_id, "recipient_agent_id")?;
    validate_ascii_line(transfer_id, "transfer_id")?;
    validate_ascii_line(action, "action")?;
    validate_nonce(nonce)?;

    if !matches!(action, "download" | "ack" | "inbox" | "request_ticket") {
        return Err(Error::Internal(format!(
            "action must be 'download', 'ack', 'inbox' or 'request_ticket', got {}",
            action
        )));
    }

    let msg = format!(
        "spize-transfer-receipt:{version}\nrecipient={rec}\ntransfer={tx}\naction={act}\nnonce={nonce}\nts={ts}",
        version = PROTOCOL_VERSION,
        rec = recipient_agent_id,
        tx = transfer_id,
        act = action,
        nonce = nonce,
        ts = issued_at_unix,
    );
    Ok(msg.into_bytes())
}

fn validate_nonce(nonce: &str) -> Result<()> {
    if nonce.len() < MIN_NONCE_LEN || nonce.len() > MAX_NONCE_LEN {
        return Err(Error::Internal(format!(
            "nonce length {} outside [{}, {}]",
            nonce.len(),
            MIN_NONCE_LEN,
            MAX_NONCE_LEN
        )));
    }
    if !nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Internal("nonce must be hex".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_stable() {
        let bytes = registration_challenge_bytes(
            "aabbcc",
            "acme",
            "alice",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let expected = "spize-register:v1\npub=aabbcc\norg=acme\nname=alice\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn different_inputs_different_bytes() {
        let a = registration_challenge_bytes(
            "aa",
            "acme",
            "alice",
            "0123456789abcdef0123456789abcdef",
            100,
        )
        .unwrap();
        let b = registration_challenge_bytes(
            "aa",
            "acme",
            "alice",
            "0123456789abcdef0123456789abcdef",
            101,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn newline_in_field_rejected() {
        let err = registration_challenge_bytes(
            "aa",
            "ac\nme",
            "alice",
            "0123456789abcdef0123456789abcdef",
            100,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn non_ascii_field_rejected() {
        let err = registration_challenge_bytes(
            "aa",
            "acmè",
            "alice",
            "0123456789abcdef0123456789abcdef",
            100,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn short_nonce_rejected() {
        let err = registration_challenge_bytes("aa", "acme", "alice", "deadbeef", 100).unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn non_hex_nonce_rejected() {
        let err = registration_challenge_bytes(
            "aa",
            "acme",
            "alice",
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
            100,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn empty_pub_rejected() {
        let err = registration_challenge_bytes(
            "",
            "acme",
            "alice",
            "0123456789abcdef0123456789abcdef",
            100,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn transfer_intent_stable() {
        let bytes = transfer_intent_bytes(
            "spize:acme/alice:aabbcc",
            "spize:acme/bob:ddeeff",
            12345,
            "application/pdf",
            "invoice.pdf",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let expected = "spize-transfer-intent:v1\nsender=spize:acme/alice:aabbcc\nrecipient=spize:acme/bob:ddeeff\nsize=12345\nmime=application/pdf\nfilename=invoice.pdf\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn transfer_intent_empty_optionals() {
        let bytes = transfer_intent_bytes(
            "spize:acme/alice:aabbcc",
            "bob@example.com",
            100,
            "",
            "",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains("mime=\n"));
        assert!(s.contains("filename=\n"));
    }

    #[test]
    fn transfer_receipt_stable() {
        let bytes = transfer_receipt_bytes(
            "spize:acme/bob:ddeeff",
            "tx_abc123",
            "ack",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let expected = "spize-transfer-receipt:v1\nrecipient=spize:acme/bob:ddeeff\ntransfer=tx_abc123\naction=ack\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn clock_skew_within_window_accepted() {
        let now = 1_700_000_000;
        assert!(is_within_clock_skew(now, now));
        assert!(is_within_clock_skew(now, now - 300));
        assert!(is_within_clock_skew(now, now + 300));
    }

    #[test]
    fn clock_skew_outside_window_rejected() {
        let now = 1_700_000_000;
        assert!(!is_within_clock_skew(now, now - 301));
        assert!(!is_within_clock_skew(now, now + 301));
    }

    #[test]
    fn clock_skew_extreme_inputs_do_not_panic() {
        // Pre-fix: `(now - issued_at).abs()` overflows on these in debug.
        let now = 1_700_000_000;
        assert!(!is_within_clock_skew(now, i64::MIN));
        assert!(!is_within_clock_skew(now, i64::MAX));
        assert!(!is_within_clock_skew(i64::MAX, i64::MIN));
    }

    #[test]
    fn transfer_receipt_rejects_bad_action() {
        let err = transfer_receipt_bytes(
            "spize:acme/bob:ddeeff",
            "tx_abc",
            "overwrite",
            "0123456789abcdef0123456789abcdef",
            1,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn data_ticket_stable() {
        let bytes = data_ticket_bytes(
            "tx_abc123",
            "spize:acme/bob:ddeeff",
            "https://data.spize.io",
            1_700_000_100,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let expected = "spize-data-ticket:v1\ntransfer=tx_abc123\nrecipient=spize:acme/bob:ddeeff\ndata_plane=https://data.spize.io\nexpires=1700000100\nnonce=0123456789abcdef0123456789abcdef";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn rotate_key_stable() {
        let bytes = rotate_key_challenge_bytes(
            "spize:acme/alice:aabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let expected = "spize-rotate-key:v1\nagent=spize:acme/alice:aabbcc\nold_pub=1111111111111111111111111111111111111111111111111111111111111111\nnew_pub=2222222222222222222222222222222222222222222222222222222222222222\nnonce=0123456789abcdef0123456789abcdef\nts=1700000000";
        assert_eq!(bytes, expected.as_bytes());
    }

    #[test]
    fn rotate_key_different_new_key_yields_different_bytes() {
        let a = rotate_key_challenge_bytes(
            "spize:acme/alice:aabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        let b = rotate_key_challenge_bytes(
            "spize:acme/alice:aabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "3333333333333333333333333333333333333333333333333333333333333333",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rotate_key_rejects_same_old_and_new() {
        let err = rotate_key_challenge_bytes(
            "spize:acme/alice:aabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn rotate_key_rejects_newline_in_agent_id() {
        let err = rotate_key_challenge_bytes(
            "spize:acme/alice:\naabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "0123456789abcdef0123456789abcdef",
            1_700_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn rotate_key_rejects_short_nonce() {
        let err = rotate_key_challenge_bytes(
            "spize:acme/alice:aabbcc",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "deadbeef",
            1_700_000_000,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }

    #[test]
    fn data_ticket_rejects_newline_url() {
        let err = data_ticket_bytes(
            "tx_abc",
            "spize:acme/bob:ddeeff",
            "https://evil.test\nspoof",
            1,
            "0123456789abcdef0123456789abcdef",
        )
        .unwrap_err();
        assert!(matches!(err, Error::Internal(_)));
    }
}
