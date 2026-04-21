# Security

## Reporting a vulnerability

Please email **info@micheletrani.com** with the subject line `AEX security report`.
Include a short reproduction, the commit hash, and your contact. We aim to
acknowledge within 72 hours.

Do **not** open a public GitHub issue for security bugs.

## Deployment checklist (control plane)

The control plane ships secure-by-default for local development. These items
are the responsibility of the operator deploying it:

| Concern | Status | Operator action |
|---|---|---|
| Signature verification on every write endpoint | ✅ enforced in code | — |
| Nonce replay protection (registration + intent) | ✅ enforced via Postgres `UNIQUE` | — |
| Clock skew rejection (±300s, overflow-safe) | ✅ `spize_core::wire::is_within_clock_skew` | — |
| Blob files 0600 | ✅ `FileBlobStore::put` | — |
| Control-plane signing key 0600 + atomic write | ✅ `ControlPlaneSigner::persist` | — |
| Request body cap (500 MB) | ✅ `RequestBodyLimitLayer` | — |
| CORS | ⚠️ empty by default | Set `CORS_ALLOWED_ORIGINS` to your dashboard origin |
| Rate limiting | ❌ not in code | Terminate behind Cloudflare / nginx and rate-limit at the edge. In-process `tower_governor` middleware is a Phase 2 addition. |
| Admin authentication | ❌ not yet implemented | Dashboard (`/dashboard`) is read-only and operator-local. Do NOT expose publicly until admin auth ships (M4). |
| `LOG_FORMAT=json` for production | ⚠️ optional | Set for aggregator ingestion. |
| Supabase `sap_waitlist` RLS | ⚠️ operator-owned | Confirm RLS is enabled on the table; anon key is public by design. |
| Rekor submission for audit | ⚠️ stub only | `HttpRekorSubmitter` (Phase G1-real) ships the wrapper today; integrate against `rekor.sigstore.dev` when ready. |
| Stripe billing | ⚠️ skeleton only | Replace `StripeBilling::record_usage` skeleton with real meter POSTs when dashboard config exists. |

## MCP server threat model

`@spize/mcp-server` bridges an LLM host (Claude Desktop, Cursor, etc.) to a
Spize control plane. LLM-supplied arguments are treated as **untrusted**:

- `spize_send` — `recipient` is validated against the four allowed formats
  (spize-native, did:{ethr,web,key}, email, phone) in
  [`packages/mcp-server/src/index.ts`](./packages/mcp-server/src/index.ts). A
  typo'd LLM output cannot silently route to the human-bridge path.
- `spize_download` — returned bytes are wrapped in
  `<untrusted-content source="spize-transfer:tx_…">…</untrusted-content>`
  and carry an explicit `trust_warning` field. LLM hosts should treat the
  content as data, not instructions (second-order prompt injection defence).
- `spize_init` — creates + registers + persists an identity. First
  invocation is interactive-by-assumption (the user sees the MCP prompt).

The MCP server does **not** enforce a recipient allowlist or require human
confirmation before each send. That is a product decision tied to M2
alpha UX; operators concerned about LLM-initiated exfiltration should
either scope the SPIZE_IDENTITY_FILE to a disposable identity or front
the control plane with a review proxy.

## CI/CD pipeline

- Third-party actions are pinned to commit SHAs. See
  [`.github/workflows/build.yml`](./.github/workflows/build.yml).
- [`.github/dependabot.yml`](./.github/dependabot.yml) bumps pinned SHAs
  weekly across github-actions / cargo / npm / pip ecosystems.
- [`.github/CODEOWNERS`](./.github/CODEOWNERS) requires owner review for
  changes under `/.github/**`, `spize-core/**`, `spize-identity/**`, and
  the control-plane signer + routes.

## Cryptography

- **Ed25519** via `ed25519-dalek` (Rust), `@noble/ed25519` (TS), and
  `cryptography` (Python). Same canonical byte strings signed across all
  three, enforced by a cross-language golden-vector test.
- **ECDSA secp256k1** via `k256` (Rust) for `did:ethr` identities through
  the `EtereCitizenProvider`.
- Identity fingerprint is the first 3 bytes of SHA-256 over the public
  key. The full public key is the authoritative unique identifier
  (Postgres `UNIQUE` on `agents.public_key`); the fingerprint is a
  human-friendly tie-breaker.
- Keys are stored as raw 32-byte files with `0o600` perms. No KMS
  integration yet; HSM-backed `ControlPlaneSigner` is Phase 2.

## Known limitations

or the "Remediation priority" section from the most recent run. Open
items live in `TODOS.md` (to be added) with `security` labels.
