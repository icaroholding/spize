//! Tamper-evident audit log.
//!
//! Every business-meaningful action in the Agent Exchange Protocol (AEX) — agent
//! registration, transfer initiation, scanner verdict, policy decision,
//! delivery, revocation — writes an [`Event`] to an [`AuditLog`].
//!
//! # Integrity model
//!
//! Events are **hash-chained**: each event stores the hash of the previous
//! event. This means any retroactive modification of an event breaks the
//! chain for every event that followed — you cannot rewrite history without
//! producing a visibly different chain head.
//!
//! Chain-head hashes are the basis for future Merkle-batching and Sigstore
//! Rekor submission (Phase G1). When that lands, the interface here does
//! not change — [`AuditLog::current_head`] just starts being submitted to
//! Rekor periodically.
//!
//! # Implementations
//!
//! - [`MemoryAuditLog`] — in-memory, used by tests and M1 demo.
//! - [`FileAuditLog`] — append-only JSONL file, one line per event. Used
//!   by the dev-tier control plane.
//! - *(Phase 2)* `PostgresAuditLog` — events in Postgres with a maintained
//!   `chain_head` table for fast reads.
//! - *(Phase G1)* `RekorAnchoredAuditLog<Inner>` — wraps any inner log and
//!   periodically submits chain heads to the Sigstore Rekor transparency
//!   log.

pub mod error;
pub mod event;
pub mod file_log;
pub mod memory_log;
pub mod rekor;

pub use error::{AuditError, AuditResult};
pub use event::{Event, EventKind, EventReceipt};
pub use file_log::FileAuditLog;
pub use memory_log::MemoryAuditLog;
pub use rekor::{
    LoggingRekorSubmitter, RekorAnchoredAuditLog, RekorReceipt, RekorSubmitter, StubRekorSubmitter,
};

use async_trait::async_trait;

/// Core audit log trait.
///
/// Implementations must be internally synchronized — concurrent callers
/// must see a serialized view of the chain. No external locking required.
#[async_trait]
#[allow(clippy::len_without_is_empty)]
pub trait AuditLog: Send + Sync {
    /// Append an event to the log. Returns a receipt the caller can keep
    /// as proof the event is recorded (contains event id + chain head at
    /// the time of append).
    async fn append(&self, event: Event) -> AuditResult<EventReceipt>;

    /// The current chain head: hex-encoded hash of the last appended event,
    /// or the genesis sentinel if the log is empty.
    async fn current_head(&self) -> AuditResult<String>;

    /// Replay the full chain, verifying every stored hash against the
    /// canonical bytes of the event. Returns `Ok(())` if the chain is
    /// intact; errors identify the first event at which verification failed.
    async fn verify_chain(&self) -> AuditResult<()>;

    /// Total number of events appended since genesis.
    async fn len(&self) -> AuditResult<u64>;
}

/// Sentinel value used as the `prev_hash` of the first event in a fresh
/// chain. Chosen as the all-zeros 32-byte hash encoded as hex — sha256 of
/// the empty string would also work, but all-zeros is unambiguous and does
/// not accidentally match any real event.
pub const GENESIS_HEAD: &str = "0000000000000000000000000000000000000000000000000000000000000000";
