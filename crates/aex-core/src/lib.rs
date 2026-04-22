//! Core types, traits, and errors for Agent Exchange Protocol (AEX).
//!
//! This crate defines the shared vocabulary used across the control plane,
//! SDKs, and identity/scanner/policy/audit providers. It intentionally has
//! no crypto or IO dependencies — those live in per-concern crates that
//! implement the traits defined here.

pub mod endpoint;
pub mod error;
pub mod identity;
pub mod signature;
pub mod types;
pub mod wire;

pub use endpoint::{Endpoint, EndpointHealth, HealthStatus};
pub use error::{Error, Result};
pub use identity::{IdentityProvider, TrustMetadata};
pub use signature::{Signature, SignatureAlgorithm};
pub use types::{AgentId, IdScheme, TransferId};
