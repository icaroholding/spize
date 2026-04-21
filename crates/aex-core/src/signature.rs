use serde::{Deserialize, Serialize};

/// The signature algorithm used to produce a [`Signature`].
///
/// New variants are added as we onboard identity schemes. Do NOT repurpose
/// existing variants — audit entries reference these values forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureAlgorithm {
    /// Ed25519 — used by the native Spize identity provider.
    Ed25519,
    /// ECDSA over secp256k1 — used by DID-ethr / EtereCitizen identities
    /// (Ethereum-compatible wallet signatures).
    EcdsaSecp256k1,
}

/// A cryptographic signature over an opaque byte string.
///
/// The interpretation of `bytes` depends on `algorithm`:
/// - `Ed25519`: 64-byte signature as per RFC 8032.
/// - `EcdsaSecp256k1`: 65-byte (r || s || v) Ethereum signature format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algorithm: SignatureAlgorithm,
    #[serde(with = "hex_bytes")]
    pub bytes: Vec<u8>,
}

/// Serialize `Vec<u8>` as hex string (avoid bloating JSON with base64-looking blobs).
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        hex_decode(&s).map_err(serde::de::Error::custom)
    }

    fn hex_encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
        if !s.len().is_multiple_of(2) {
            return Err(format!("odd hex length: {}", s.len()));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        for i in (0..s.len()).step_by(2) {
            let byte = u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at {}: {}", i, e))?;
            out.push(byte);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_ed25519() {
        let sig = Signature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("deadbeef"));
        assert!(json.contains("ed25519"));
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }

    #[test]
    fn serde_roundtrip_ecdsa() {
        let sig = Signature {
            algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            bytes: vec![0x01, 0x02, 0x03],
        };
        let json = serde_json::to_string(&sig).unwrap();
        assert!(json.contains("ecdsa-secp256k1"));
        let back: Signature = serde_json::from_str(&json).unwrap();
        assert_eq!(sig, back);
    }
}
