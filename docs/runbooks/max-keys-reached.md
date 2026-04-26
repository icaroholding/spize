# Runbook: max api keys per customer reached

## Symptom

- **Status:** `409 Conflict`
- **`code`:** `conflict`
- **Message:** `max 10 active api keys per customer; revoke one
  before minting another`

## Likely cause

The customer has the maximum number of simultaneous active api
keys (10) and is trying to mint another. The cap exists to limit
blast radius if the dashboard is compromised — even a hostile
session can't enumerate-and-mint forever.

## Remediation

The customer should revoke an existing key from the dashboard
("API Keys" section, "Revoke" button), then retry the mint. The
freed slot opens immediately — `revoked_at` is set on revoke and
the active-key counter excludes those rows.

If you have a legitimate reason to allow more (an enterprise
customer with many service accounts), the cap is `MAX_ACTIVE_KEYS_PER_CUSTOMER`
in `crates/aex-control-plane/src/routes/customer/api_keys.rs`.
Bumping it requires a code change + redeploy; alternatively,
expose a per-tier cap (enterprise = 100, team = 25, dev = 10) once
the tier matrix grows.

## Related

- `crates/aex-control-plane/src/routes/customer/api_keys.rs::mint`
- `crates/aex-control-plane/src/routes/customer/api_keys.rs::MAX_ACTIVE_KEYS_PER_CUSTOMER`
