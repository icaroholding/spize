# Runbook: `api key required`

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** `api key required`

You called a `/v1/metered/*` endpoint without presenting an API key
on any recognised header.

## Likely cause

1. **Header omitted.** The metered surface requires authentication on
   every request. There is no anonymous access tier.
2. **Wrong header name.** We read `X-API-Key` (preferred) and
   `Authorization: Bearer …` (fallback). Any other header — including
   `Authorization: Basic`, `Api-Key`, or `X-Auth-Token` — is ignored.
3. **Empty value.** A header that exists but resolves to whitespace
   after trimming is treated the same as missing.

## Remediation

Attach the plaintext key you received at mint time on either header:

```bash
# Preferred: custom header (no CORS preflight on simple GETs).
curl -sS https://api.spize.io/v1/metered/whoami \
    -H "X-API-Key: aex_live_0123456789abcdef0123456789abcdef"

# Fallback: Authorization Bearer. Works from browser fetch() without
# a custom-header preflight.
curl -sS https://api.spize.io/v1/metered/whoami \
    -H "Authorization: Bearer aex_live_0123456789abcdef0123456789abcdef"
```

If you don't have a key, an operator with admin access can mint one:

```bash
curl -sS https://api.spize.io/v1/admin/api-keys \
    -X POST \
    -H "Authorization: Bearer $AEX_ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"customer_id":"cust_abc","name":"my app","tier":"dev"}'
# → { "api_key": "aex_live_…", ... }   <- shown ONCE, save it.
```

## Related

- [api-key-invalid](api-key-invalid.md) — key was present but
  rejected.
- `crates/aex-control-plane/src/routes/metered.rs::require_api_key`
