# Runbook: `nonce length out of range` / `nonce must be hex`

## Symptom

- **Status:** `400 Bad Request`
- **`code`:** `bad_request`
- **Message:** `nonce length must be 32..=128 hex chars` or
  `nonce must be hex`

## Likely cause

Custom payload construction that bypasses the SDK's
`random_nonce()` helper. The CP accepts nonces that are exactly
32-128 hex characters long; anything else fails shape validation
before any crypto runs.

## Remediation

Use the SDK helper:

- Python: `from aex_sdk.identity import random_nonce; nonce = random_nonce()`
- TypeScript: `import { randomNonce } from "@aexproto/sdk"; const nonce = randomNonce();`
- Rust: see `tests/common/mod.rs::random_nonce` for the reference
  implementation (16 bytes of CSPRNG → hex).

If you can't use the SDK, generate 16-32 cryptographically random
bytes and hex-encode. The minimum-entropy requirement (128 bits)
exists to make replay tables infeasible.

## Related

- `MIN_NONCE_LEN` / `MAX_NONCE_LEN` in `crates/aex-core/src/wire.rs`
- `validate_nonce` in the same file
