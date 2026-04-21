#![allow(clippy::len_without_is_empty)]

//! EtereCitizen identity provider.
//!
//! `did:ethr:<chainId>:<address>` identities backed by an Ethereum-style
//! secp256k1 keypair. For M3 we ship an in-memory registry + stub
//! reputation fetcher; Phase 2 swaps the registry for a Base L2 RPC
//! client that reads EtereCitizen's on-chain registry and reputation
//! index.
//!
//! # Why it lives behind the same trait
//!
//! [`IdentityProvider`] is generic over the identity scheme. The control
//! plane dispatches by the `AgentId` scheme prefix:
//! `spize:…` → [`SpizeNativeProvider`](crate::SpizeNativeProvider),
//! `did:ethr:…` → [`EtereCitizenProvider`]. Consumers never branch on
//! provider type; they just call `.verify_peer(…)` on whichever provider
//! handles the incoming id.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature as K256Signature, SigningKey, VerifyingKey,
};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

use aex_core::{
    AgentId, Error, IdentityProvider, Result, Signature, SignatureAlgorithm, TrustMetadata,
};

/// Default chain id for EtereCitizen on Base mainnet. Kept here so
/// tests and docs agree with the default provider wiring.
pub const DEFAULT_CHAIN_ID: u64 = 8453;

/// In-memory registry mapping `did:ethr` ids to their verifying keys and
/// optional reputation metadata.
///
/// Swap with a Base-L2-backed implementation in Phase 2 — the control
/// plane calls this trait, not the struct directly.
#[derive(Default)]
pub struct EtereCitizenRegistry {
    peers: RwLock<HashMap<AgentId, VerifyingKey>>,
    reputation: RwLock<HashMap<AgentId, TrustMetadata>>,
}

impl EtereCitizenRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn register(&self, agent_id: AgentId, public_key: VerifyingKey) {
        self.peers.write().await.insert(agent_id, public_key);
    }

    pub async fn set_reputation(&self, agent_id: AgentId, metadata: TrustMetadata) {
        self.reputation.write().await.insert(agent_id, metadata);
    }

    pub async fn lookup(&self, agent_id: &AgentId) -> Option<VerifyingKey> {
        self.peers.read().await.get(agent_id).copied()
    }

    pub async fn reputation(&self, agent_id: &AgentId) -> Option<TrustMetadata> {
        self.reputation.read().await.get(agent_id).cloned()
    }

    pub async fn len(&self) -> usize {
        self.peers.read().await.len()
    }
}

/// Optional trait letting tests plug in custom reputation sources.
#[async_trait]
pub trait ReputationFetcher: Send + Sync {
    async fn fetch(&self, agent_id: &AgentId) -> Option<TrustMetadata>;
}

#[async_trait]
impl ReputationFetcher for EtereCitizenRegistry {
    async fn fetch(&self, agent_id: &AgentId) -> Option<TrustMetadata> {
        self.reputation(agent_id).await
    }
}

pub struct EtereCitizenProvider {
    agent_id: AgentId,
    signing_key: SigningKey,
    registry: Arc<EtereCitizenRegistry>,
    reputation: Arc<dyn ReputationFetcher>,
}

impl EtereCitizenProvider {
    /// Generate a fresh secp256k1 keypair, derive an EVM address, and
    /// build the matching `did:ethr:{chain}:{address}` id.
    pub fn generate(chain_id: u64, registry: Arc<EtereCitizenRegistry>) -> Result<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        Self::from_signing_key(chain_id, signing_key, registry)
    }

    pub fn from_secret_bytes(
        chain_id: u64,
        secret: [u8; 32],
        registry: Arc<EtereCitizenRegistry>,
    ) -> Result<Self> {
        let signing_key = SigningKey::from_bytes((&secret).into())
            .map_err(|e| Error::Crypto(format!("bad secp256k1 secret: {}", e)))?;
        Self::from_signing_key(chain_id, signing_key, registry)
    }

    fn from_signing_key(
        chain_id: u64,
        signing_key: SigningKey,
        registry: Arc<EtereCitizenRegistry>,
    ) -> Result<Self> {
        let verifying_key = *signing_key.verifying_key();
        let address = evm_address(&verifying_key);
        let id_str = format!("did:ethr:{}:0x{}", chain_id, address);
        let agent_id = AgentId::new(id_str)?;
        let reputation: Arc<dyn ReputationFetcher> = registry.clone();
        Ok(Self {
            agent_id,
            signing_key,
            registry,
            reputation,
        })
    }

    pub fn with_reputation_fetcher(mut self, f: Arc<dyn ReputationFetcher>) -> Self {
        self.reputation = f;
        self
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    pub fn registry(&self) -> &EtereCitizenRegistry {
        &self.registry
    }
}

/// EIP-55-ignoring EVM address derivation: last 20 bytes of
/// keccak256(uncompressed_pubkey_without_0x04_prefix). We approximate
/// keccak with sha3 variant? No — Ethereum uses keccak-256 specifically.
/// To keep deps light we use sha3's keccak256 via a re-export already in
/// the workspace. If that isn't available, fall back to sha256-based
/// addresses; real EtereCitizen integration in Phase 2 will use the
/// `alloy-primitives` crate.
fn evm_address(vk: &VerifyingKey) -> String {
    // Uncompressed form is 0x04 || X(32) || Y(32) — strip the 0x04 prefix.
    let encoded = vk.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    let without_prefix = &bytes[1..];
    // Use SHA-256 as a stand-in for keccak for THIS MVP. Real addresses
    // require keccak-256; we document the divergence and fix in Phase 2.
    let digest = Sha256::digest(without_prefix);
    hex::encode(&digest[digest.len() - 20..])
}

#[async_trait]
impl IdentityProvider for EtereCitizenProvider {
    fn agent_id(&self) -> &AgentId {
        &self.agent_id
    }

    async fn sign(&self, message: &[u8]) -> Result<Signature> {
        let sig: K256Signature = self.signing_key.sign(message);
        // ECDSA-secp256k1 fixed-length signatures are 64 bytes (r || s).
        // We ship the fixed-length form; recovery id (+27/+28) is appended
        // later when we integrate with Ethereum signed-message envelopes.
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&sig.to_bytes());
        Ok(Signature {
            algorithm: SignatureAlgorithm::EcdsaSecp256k1,
            bytes,
        })
    }

    async fn verify_peer(
        &self,
        peer_id: &AgentId,
        message: &[u8],
        signature: &Signature,
    ) -> Result<()> {
        if signature.algorithm != SignatureAlgorithm::EcdsaSecp256k1 {
            return Err(Error::SignatureFormat(format!(
                "EtereCitizen only accepts EcdsaSecp256k1, got {:?}",
                signature.algorithm
            )));
        }
        if signature.bytes.len() != 64 {
            return Err(Error::SignatureFormat(format!(
                "expected 64 bytes, got {}",
                signature.bytes.len()
            )));
        }

        let vk = self.registry.lookup(peer_id).await.ok_or_else(|| {
            Error::NotFound(format!("peer {} not in EtereCitizen registry", peer_id))
        })?;

        let sig = K256Signature::from_slice(&signature.bytes)
            .map_err(|e| Error::SignatureFormat(format!("malformed ecdsa: {}", e)))?;

        vk.verify(message, &sig)
            .map_err(|_| Error::SignatureInvalid)
    }

    async fn trust_metadata(&self, peer_id: &AgentId) -> Option<TrustMetadata> {
        self.reputation.fetch(peer_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sign_and_verify_roundtrip() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let alice = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        let bob = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        reg.register(alice.agent_id().clone(), alice.verifying_key())
            .await;
        reg.register(bob.agent_id().clone(), bob.verifying_key())
            .await;

        let msg = b"hello from alice";
        let sig = alice.sign(msg).await.unwrap();
        bob.verify_peer(alice.agent_id(), msg, &sig).await.unwrap();
    }

    #[tokio::test]
    async fn tampered_message_rejected() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let alice = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        let bob = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        reg.register(alice.agent_id().clone(), alice.verifying_key())
            .await;
        reg.register(bob.agent_id().clone(), bob.verifying_key())
            .await;

        let sig = alice.sign(b"hello").await.unwrap();
        let err = bob
            .verify_peer(alice.agent_id(), b"hxllo", &sig)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureInvalid));
    }

    #[tokio::test]
    async fn unknown_peer_rejected() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let alice = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        let bob = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        // alice NOT registered
        let sig = alice.sign(b"hi").await.unwrap();
        let err = bob
            .verify_peer(alice.agent_id(), b"hi", &sig)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[tokio::test]
    async fn wrong_algorithm_rejected() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let alice = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        let bob = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        reg.register(alice.agent_id().clone(), alice.verifying_key())
            .await;
        reg.register(bob.agent_id().clone(), bob.verifying_key())
            .await;

        let wrong = Signature {
            algorithm: SignatureAlgorithm::Ed25519,
            bytes: vec![0u8; 64],
        };
        let err = bob
            .verify_peer(alice.agent_id(), b"hi", &wrong)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::SignatureFormat(_)));
    }

    #[tokio::test]
    async fn trust_metadata_surface() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let alice = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        let bob = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg.clone()).unwrap();
        reg.register(bob.agent_id().clone(), bob.verifying_key())
            .await;
        reg.set_reputation(
            bob.agent_id().clone(),
            TrustMetadata {
                verification_level: Some(3),
                reputation_score: Some(4.7),
                review_count: Some(52),
                capabilities: vec!["research".into()],
                flags: vec![],
            },
        )
        .await;

        let meta = alice.trust_metadata(bob.agent_id()).await.unwrap();
        assert_eq!(meta.verification_level, Some(3));
        assert_eq!(meta.review_count, Some(52));
    }

    #[test]
    fn agent_id_format() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let p = EtereCitizenProvider::generate(DEFAULT_CHAIN_ID, reg).unwrap();
        assert!(p.agent_id().as_str().starts_with("did:ethr:8453:0x"));
    }

    #[test]
    fn deterministic_from_secret() {
        let reg = Arc::new(EtereCitizenRegistry::new());
        let secret = [3u8; 32];
        let a =
            EtereCitizenProvider::from_secret_bytes(DEFAULT_CHAIN_ID, secret, reg.clone()).unwrap();
        let b = EtereCitizenProvider::from_secret_bytes(DEFAULT_CHAIN_ID, secret, reg).unwrap();
        assert_eq!(a.agent_id(), b.agent_id());
    }
}
