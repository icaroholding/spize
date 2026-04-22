//! Tunnel providers for the Spize data plane.
//!
//! The tunnel layer gives a locally-bound HTTP server a public URL so
//! peers across the internet can reach it. Each provider is a different
//! way of achieving that:
//!
//! - [`CloudflareQuickTunnel`] — wraps `cloudflared tunnel --url …`.
//!   Zero-config but ephemeral URL (regenerated on every restart).
//! - [`NamedCloudflareTunnel`] — persistent hostname via a Cloudflare
//!   named tunnel (operator-configured token + public URL).
//! - [`IrohTunnel`] — QUIC peer-to-peer via iroh, with DERP relay
//!   fallback. Added in Sprint 2 per ADR-0002 + ADR-0015.
//! - [`TailscaleFunnelTunnel`] — public funnel URL via Tailscale.
//! - [`FrpTunnel`] — self-hosted reverse proxy (frpc → frps).
//! - [`StubTunnel`] — in-process no-op used by tests. Returns a fixed URL
//!   without starting any process.
//!
//! [`TunnelOrchestrator`] composes a slice of providers and exposes the
//! union of their reachable endpoints as an `aex-core` `Endpoint[]` —
//! see ADR decision 1B (keep single-URL providers, compose at a layer
//! above).

pub mod cloudflare;
pub mod cloudflare_named;
pub mod error;
pub mod frp;
pub mod iroh;
pub mod orchestrator;
pub mod provider;
pub mod stub;
pub mod tailscale;
mod url_parser;

pub use cloudflare::CloudflareQuickTunnel;
pub use cloudflare_named::NamedCloudflareTunnel;
pub use error::{TunnelError, TunnelResult};
pub use frp::{FrpServer, FrpTunnel};
pub use iroh::{IrohTunnel, IROH_ALPN};
pub use orchestrator::{TransportEntry, TransportStartOutcome, TunnelOrchestrator};
pub use provider::{TunnelProvider, TunnelStatus};
pub use stub::StubTunnel;
pub use tailscale::TailscaleFunnelTunnel;

#[cfg(test)]
pub use url_parser::extract_tunnel_url;
