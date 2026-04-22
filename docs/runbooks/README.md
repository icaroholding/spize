# AEX Runbooks

Operator-facing remediation pages for the most common Agent Exchange Protocol
failure modes. Every non-generic error response from `aex-control-plane`
carries a `runbook_url` pointing at one of the files in this directory.

Each page follows the same structure:

- **Symptom** — what the caller sees on the wire (status code + `code`
  field + typical message).
- **Likely cause** — the handful of real-world reasons this error fires.
- **Remediation** — copy-pasteable steps to unstick the caller.
- **Related** — ADRs and source modules to consult if the remediation
  above doesn't apply.

## Mapping

| Runbook | Typical trigger |
|---|---|
| [agent-already-exists](agent-already-exists.md) | `POST /v1/agents/register` conflicts on pubkey or agent_id |
| [agent-not-found](agent-not-found.md) | `GET /v1/agents/:id` for an identity the CP doesn't know |
| [agent-not-registered-or-revoked](agent-not-registered-or-revoked.md) | Signed request from an agent with no active key |
| [clock-skew](clock-skew.md) | `issued_at` outside the ±300 s window |
| [conflict](conflict.md) | Generic 409 we haven't enumerated more specifically |
| [endpoint-unreachable](endpoint-unreachable.md) | `reachable_at[]` validation failed for every entry |
| [internal-error](internal-error.md) | 500 — see server logs |
| [malformed-nonce](malformed-nonce.md) | Nonce wrong length / non-hex |
| [nonce-replay](nonce-replay.md) | A previously-consumed nonce was re-sent |
| [rotation-race](rotation-race.md) | Two concurrent `rotate-key` calls |
| [signature-invalid](signature-invalid.md) | Ed25519 check failed against the current key |
| [transfer-not-found](transfer-not-found.md) | `/v1/transfers/:id` for a vanished id |
| [unauthorized](unauthorized.md) | Generic 401 not otherwise enumerated |
| [wrong-recipient](wrong-recipient.md) | Recipient tried to operate on someone else's transfer |

## Pinning

Runbook URLs in error responses point at this repo's `master` branch so a
deployed v1.x CP can hand out links that resolve as long as the repo
stays public. If you fork, update
`crates/aex-control-plane/src/error.rs::runbook::BASE_URL`.
