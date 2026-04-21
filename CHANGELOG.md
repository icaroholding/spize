# Changelog

All notable changes are recorded here. Versioning follows [semver](https://semver.org).

## Unreleased — targeting `v1.3.0-beta.1`

Sprint 1.5 scope: `aex-net` crate + SDK DoH parity + protocol §5
normative spec + 37 ADRs + two data-plane CLI delights. Wire format
stays v1 in this sprint; breaking `reachable_at[]` migration and
Iroh first-class transport land in Sprint 2 with the `v1.3.0-beta.1`
tag.

### Added
- `aex-net` crate — shared DNS-over-HTTPS resolver, HTTP client
  factory (`build_http_client(component)` + `_with_timeout`), normative
  retry policy, and captive-portal detection via three standard probe
  endpoints. Single home for the network-layer quirks the four Sprint 1
  DNS commits (search-domain suffix, NXDOMAIN cache, UDP/53
  interception, DoH fallback) were hitting.
- Python SDK `aex_sdk.resolver` / `aex_sdk.retry` / `aex_sdk.captive`.
  `SpizeClient` accepts a `resolver=` kwarg; `fetch_from_tunnel` plus
  the new `upload_blob_admin` helper route through a DoH transport
  (dnspython over HTTP/2, Cloudflare 1.1.1.1 bootstrap pinned).
- TypeScript SDK `resolver.ts` / `retry.ts` / `captive.ts`.
  `SpizeClient` accepts a `resolver` option; tangerine-backed DoH via
  an `undici.Agent` with `connect.lookup`. Node.js only; browser
  builds pass the platform `fetch` through unchanged.
- `docs/protocol-v1.md` §5 "Normative network behaviour": §5.1 retry
  policy (3 attempts, 1 s base, 2× multiplier, ±100 ms jitter), §5.3
  captive-portal detection (Apple / Google / MS NCSI probes, consensus
  rules, stdout token set). Conformance test at
  `crates/aex-net/tests/conformance/` pins the Rust side values.
- `docs/decisions/`: 37 ADRs transcribed from the 2026-04-21 "Network
  Sovereignty" plan review — strategic Q1-Q10, architecture, security,
  tests, observability, deployment, and long-term items.
- `aex-data-plane` CLI: `--help`, `--version`, `--version --verbose`
  (Delight #6; dumps compiled transports + DNS config + repo URL).
- `aex-data-plane` stdout: `AEX_NETWORK_STATE=<direct|captive_portal|
  limited|unknown>` emitted at startup after the §5.3 probe consensus
  (Delight #5). Advisory only — orchestrators surface it to operators,
  never gate execution.
- `TODOS.md` at repo root tracking follow-ups deferred from the
  Sprint 1.5 plan-eng-review (`verify_tunnel_reachable` extraction,
  retry-loop centralisation, chaos-testbed captive-portal scenario).

### Changed
- `aex-control-plane/src/routes/transfers.rs` drops its inline 48-LOC
  `CloudflareDnsResolver` struct and consumes
  `aex_net::build_http_client_with_timeout` instead. Behaviour
  identical.
- `hickory-resolver`, `reqwest`, `url` promoted to
  `[workspace.dependencies]`; individual crates reference
  `{ workspace = true }`.
- `demo_two_agents_cloudflare.py` no longer shells out to `curl
  --resolve` or `dig`. All HTTP goes through `SpizeClient` +
  `DoHTransport`. Verified 8/8 on a wifi network with a
  search-domain suffix — the exact failure mode Sprint 1 spent four
  commits fighting.

### Fixed
- dnspython 2.6+ defaults DoH to HTTP/3, which raises `NoDOH` when
  `aioquic` isn't installed. Pinned to HTTP/2 + required
  `httpx[http2]>=0.27` extra. Also set `bootstrap_address="1.1.1.1"`
  so the DoH endpoint itself resolves via Cloudflare anycast rather
  than the OS resolver.

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
- **Readiness invariant** in `aex-data-plane` binary: emits `AEX_DATA_PLANE_URL=…` + `AEX_READY=1` on stdout only after the tunnel's hostname resolves in public DNS AND TCP:443 accepts a connection on a resolved address. Deliberately avoids an HTTP self-roundtrip — a binary fetching its own tunnel URL is surprisingly brittle (TLS client quirks, same-host timing races with the tunnel forwarder) and that end-to-end check belongs in the control plane instead. Timeout configurable via `AEX_READINESS_TIMEOUT_SECS` (default 60s).
- **Tunnel reachability validation** in `aex-control-plane` on the M2 `send_via_tunnel` branch: before persisting the transfer, the control plane does `GET <tunnel_url>/healthz` with 3 retries (3s spacing). Requests pointing at an unreachable tunnel are rejected as 400 before the nonce is consumed. Skippable with `AEX_SKIP_TUNNEL_VALIDATION=1` for tests.

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
