//! Agent Exchange Protocol (AEX) data plane.
//!
//! The data plane is where the bytes actually move. In M2 onwards it is a
//! sender-side HTTP server that exposes a single endpoint
//! `GET /blob/:transfer_id` guarded by a short-lived signed ticket.
//!
//! # Invariants
//!
//! - Bytes never leave the sender's machine until a valid ticket is
//!   presented by the recipient.
//! - A ticket is issued by the control plane after verifying that the
//!   recipient is entitled to the transfer.
//! - Tickets are short-lived (default 60s) and single-use per transfer.
//! - The scanner pipeline runs HERE, before any byte is sent — so the
//!   control plane never sees payload content.
//!
//! # Components
//!
//! - [`TicketVerifier`] — Ed25519 signature check against the control
//!   plane's public key, with expiry + audience + replay protection.
//! - [`BlobSource`] — abstract trait to load blob bytes (filesystem,
//!   memory, tar archive of a directory, …).
//! - [`DataPlane`] — axum router + config.

pub mod blob;
pub mod error;
pub mod server;
pub mod ticket;

pub use blob::{BlobMetadata, BlobSource, FileBlobSource, InMemoryBlobSource};
pub use error::{DataPlaneError, DataPlaneResult};
pub use server::{DataPlane, DataPlaneConfig};
pub use ticket::{Ticket, TicketVerifier, VerifiedTicket};
