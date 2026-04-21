# Changelog

All notable changes are recorded here. Versioning follows [semver](https://semver.org).

## Unreleased

Planned for v1.2.0 stable:
- Admin dashboard: M2 transfer visualization
- Hosted service beta at spize.io
- Cedar DSL in `aex-policy`
- Real Rekor HTTP submitter (non-stub)
- Real Stripe HTTP calls in `aex-billing`

## [1.2.0-alpha.3] — in progress

Sprint 1 scope: close M2 end-to-end, wire release automation, correct domain references.

### Added
- `aex-tunnel::CloudflaredTunnel` — real orchestration of the `cloudflared` binary (fork + URL extraction + lifecycle)
- Integration test covering tunnel lifecycle (start → reachable → Drop → cleanup)
- MCP server M2 tools: `spize_send_via_tunnel`, `spize_request_ticket`, `spize_fetch_from_tunnel`
- TypeScript SDK M2 helpers: `sendViaTunnel`, `requestTicket`, `fetchFromTunnel`, `ticketAsHeader`, `DataPlaneTicket` type (matches the Python SDK shape)
- `transferReceiptBytes` in TS wire layer now accepts the `request_ticket` action (was already present in Rust + Python)
- npm workspaces root so `@aexproto/mcp-server` picks up `@aexproto/sdk` locally during development
- `examples/demo_two_agents_cloudflare.py` — first end-to-end demo with real Cloudflare tunnel
- **Readiness invariant** in `aex-data-plane` binary: emits `AEX_DATA_PLANE_URL=…` + `AEX_READY=1` on stdout only after a successful self-roundtrip through its own tunnel (DNS + Cloudflare edge + process). Orchestrators wait for `AEX_READY=1`; client-side reachability polls are no longer needed. Timeout configurable via `AEX_READINESS_TIMEOUT_SECS` (default 120s). Documented in the binary's module-level docs as a conformance requirement.

### Changed
- Domain references corrected from `spize.ai` to `spize.io` across README, CHANGELOG, package manifests, wire-format test fixtures, env example, code of conduct
- Workspace version bumped to `1.2.0-alpha.3`; internal `aex-*` dep pins bumped to match

### Fixed
- Version drift: `Cargo.toml` / `package.json` / `pyproject.toml` now match the published tag (prior `v1.2.0-alpha.2` tag existed but the manifests were never bumped and nothing was published — alpha.3 is the first consistent release)

## [1.2.0-alpha.2] — 2026-04-21

> Tagged in git but **not published** to any registry. Released for the record below; the actual first published release after `alpha.1` is `alpha.3`.

### Added
- `aex-data-plane` crate: axum server that streams blobs behind a signed ticket
  - `TicketVerifier` with Ed25519 sig + expiry + audience + nonce-replay checks
  - `BlobSource` trait + in-memory + filesystem implementations
  - Sender-side scanner integration (cached verdict per transfer)
- `POST /v1/transfers/:id/ticket` on `aex-control-plane` — recipient-signed request, server signs ticket
- `create_transfer` M2 branch: `tunnel_url` + `declared_size` replace `blob_hex`
- Database migration `20260420000003_data_plane.sql`: `tunnel_url` column + ticket nonce table
- Python SDK: `DataPlaneTicket`, `SpizeClient.send_via_tunnel()`, `.request_ticket()`, `.fetch_from_tunnel()`
- `examples/demo_two_agents_m2.py` — M2 flow demo

### Fixed
- `find_by_transfer_id` + `list_inbox_for_recipient` SELECTs missing `tunnel_url` column
- Public key decoding in M2 handlers (was treating BYTEA as hex)
- Wire format `transfer_receipt_bytes` now accepts `request_ticket` action
- Cargo metadata: internal `aex-*` deps now pin `version = "=1.2.0-alpha.1"`
- Workflow `dtolnay/rust-toolchain` action requires explicit `toolchain: stable` when pinned to SHA
- Clippy `-D warnings` findings across the workspace

## [1.2.0-alpha.1] — 2026-04-20

Initial public snapshot of the Agent Exchange Protocol.

### Contents
- 8 Rust crates (`aex-core`, `aex-identity`, `aex-audit`, `aex-scanner`, `aex-policy`, `aex-tunnel`, `aex-billing`, `aex-control-plane`)
  - `aex-control-plane` under BSL-1.1; rest under Apache-2.0
- Python SDK `aex-sdk` on PyPI
- TypeScript SDK `@aexproto/sdk` on npm
- MCP server `@aexproto/mcp-server` on npm
- Landing + operator dashboard + waitlist (`web/`)
- Dev Postgres via `docker compose`
- CI with fmt, clippy, tests across Rust + Python + TypeScript + web

Wire format stable: identity prefix `spize:org/name:fingerprint`, canonical signing prefixes `spize-register`, `spize-transfer-intent`, `spize-transfer-receipt`, `spize-data-ticket`. Package names use the `aex-*` / `@aexproto/` convention.
