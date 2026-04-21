//! `aex-net` — shared network utilities for the Agent Exchange Protocol (AEX).
//!
//! Small, focused building blocks reused by `aex-control-plane`, `aex-data-plane`,
//! and the Rust SDK helpers:
//!
//! - [`dns`] — [`CloudflareDnsResolver`], a `reqwest::dns::Resolve` impl that
//!   talks to 1.1.1.1 directly and bypasses the OS resolver.
//! - [`http`] — [`build_http_client`] factory that returns a `reqwest::Client`
//!   pre-configured with AEX-standard DNS, TLS, timeout, and user-agent.
//! - [`retry`] — [`RetryPolicy`] and [`retry_with_backoff`] implementing the
//!   normative AEX retry algorithm defined in `docs/protocol-v1.md` §5.1.
//! - [`captive`] — [`detect_network_state`] + [`NetworkState`] for captive-portal
//!   and degraded-network detection via three standard probe endpoints.
//!
//! # Scope
//!
//! This crate is intentionally small. It exists to centralise the network-layer
//! decisions that were re-discovered four times during Sprint 1 of the AEX rollout
//! (search-domain suffix corruption, macOS NXDOMAIN cache, UDP/53 interception,
//! and DoH fallback). Transport plurality (Iroh / Tailscale / FRP), tunnel
//! orchestration, and wire-format types live in their own crates.

#![deny(missing_docs)]

pub mod captive;
pub mod dns;
pub mod http;
pub mod retry;

pub use captive::{detect_network_state, NetworkState};
pub use dns::CloudflareDnsResolver;
pub use http::{build_http_client, build_http_client_with_timeout};
pub use retry::{retry_with_backoff, RetryPolicy};
