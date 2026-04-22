# Runbook: `api key not recognized`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** `api key not recognized`

You presented an API key on `X-API-Key` or `Authorization: Bearer`
and the control plane rejected it.

## Likely cause

1. **Typo in the plaintext.** A well-formed key is exactly 41
   characters: `aex_live_` followed by 32 hex digits. Any other shape
   — wrong prefix, wrong length, non-hex trailer — is rejected before
   we even query the database.
2. **Key was revoked.** `DELETE /v1/admin/api-keys/<id>` sets
   `revoked_at`. The auth lookup filters those rows out via the
   partial `idx_api_keys_active` index, so a revoked key is
   indistinguishable from an unknown one at the wire layer (by
   design — revelation of revocation status is an unnecessary leak).
3. **Wrong environment.** Keys minted against staging don't work on
   production, and vice versa. Check which CP URL the key was
   minted against.
4. **Copy/paste mangling.** Some chat clients insert zero-width
   joiners or "smart-quote" the key. Copy it from a terminal or a
   password manager rather than a rich-text editor.

## Remediation

1. Compare the prefix you're sending against the `key_prefix` column
   on the admin list endpoint:

    ```bash
    curl -sS https://api.spize.io/v1/admin/api-keys \
        -H "Authorization: Bearer $AEX_ADMIN_TOKEN" | jq '.keys[] | {key_prefix, revoked_at}'
    ```

   If your key's first 12 chars don't appear in the list, the key was
   never minted against this CP. If the row is present with a non-null
   `revoked_at`, the key was explicitly revoked.

2. If the prefix matches but the call still fails, the most likely
   cause is a middle-of-the-key typo. Plaintext keys are shown exactly
   once at creation time — if you don't have it saved, mint a new
   one and discard the old via `DELETE /v1/admin/api-keys/<id>`.

3. If you suspect environment mismatch, check that the CP host
   (`api.spize.io` vs a staging URL) matches the one the key was
   minted against.

## Related

- [api-key-missing](api-key-missing.md) — no key was presented at all.
- `crates/aex-control-plane/src/routes/metered.rs::require_api_key`
- `crates/aex-control-plane/src/db/api_keys.rs::find_active_by_hash`
