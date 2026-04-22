# Changelog

All notable changes are recorded here. Versioning follows [semver](https://semver.org).

## [1.3.0-beta.1] — 2026-04-22

First beta release after Sprint 2. Bundles transport plurality,
formal key rotation, and the ADR-0011 keypair bridge. Sprint 1.5's
`aex-net` crate + protocol §5 spec are included here too — alpha.3
was a git snapshot and never published, so this is the first public
release after alpha.1.

### Added (Sprint 2)
- **Transport plurality** — `Endpoint { kind, url, priority,
  health_hint_unix }` and `transfers.reachable_at JSONB`.
  Transfer creation accepts `reachable_at[]` and the control plane
  probes every entry in parallel under a 50-permit semaphore + 15 s
  budget, dropping unhealthy endpoints before persisting.
  Providers: `CloudflareQuickTunnel` (ephemeral), `NamedCloudflareTunnel`
  (persistent), `IrohTunnel` (P2P via iroh `=0.96.0`),
  `TailscaleFunnelTunnel`, `FrpTunnel`.
- **`aex-tunnel::TunnelOrchestrator`** — composes multiple providers
  into the sender's `reachable_at[]` (ADR decision 1B: keep
  single-URL providers, compose at a layer above).
- **Formal key rotation protocol** (ADR-0024) — `spize-rotate-key:v1`
  canonical message signed by the outgoing key. `POST /v1/agents/rotate-key`
  records the new key with `valid_from = now()` and sets the previous
  key's `valid_to = now() + 24 h`. During that 24 h grace window
  signatures from EITHER key verify, so in-flight receipts don't
  bounce on rotation. Backed by the new `agent_keys` table with a
  partial `UNIQUE (agent_id) WHERE valid_to IS NULL` index that makes
  "two active keys for one agent" physically impossible.
- **`aex_control_plane::clock::Clock` trait** — injected into
  `AppState` so tests can advance time deterministically across the
  24 h grace boundary. Production uses `SystemClock`; tests use
  `FrozenClock`.
- **Python / TypeScript SDK rotation** — `SpizeClient.rotate_key(new_identity)`
  / `SpizeClient.rotateKey(newIdentity)` + the canonical
  `rotate_key_challenge_bytes` helper in both `aex_sdk.wire` and
  `@aexproto/sdk`'s `wire.ts`. Both refuse cross-agent / identical-key
  rotations before hitting the network.
- **ADR-0011 keypair bridge** — `IrohTunnel::with_secret_key_bytes(&[u8; 32])`
  accepts the raw bytes from
  `aex_identity::SpizeNativeProvider::secret_key_bytes`, so the Iroh
  `EndpointId` is the same Ed25519 public key that backs the
  `spize:org/name:fingerprint`. Pure-crypto invariant test in
  `crates/aex-tunnel/tests/adr_0011_keypair_bridge.rs`.
- **`AEX_TRANSPORTS_JSON` stdout** — the `aex-data-plane` binary emits
  a machine-readable `{"transports":[Endpoint…]}` line after
  `AEX_READY=1`, so orchestrators can forward the payload verbatim
  into `POST /v1/transfers`'s `reachable_at[]`. Delight #2 from the
  Sprint 2 plan.
- **Zero-config `cloudflared` preflight** — the data plane
  fail-fasts with an actionable install hint when the default
  `AEX_TUNNEL_PROVIDER=cloudflare` is used but the binary isn't on
  `PATH`. Delight #4.

### Added (Sprint 1.5)

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

## [1.2.0-alpha.3] — skipped (not published)

> Workspace manifests ran at `1.2.0-alpha.3` during Sprint 1 / 1.5 as
> an internal snapshot. Never tagged, never published to any registry.
> The alpha.3 changes listed below are included in the `v1.3.0-beta.1`
> release above, which is the first public successor to `alpha.1`.

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
