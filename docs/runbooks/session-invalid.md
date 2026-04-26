# Runbook: session cookie missing / invalid / expired

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** one of:
  - `session cookie missing` — no `aex_session` cookie on the
    request.
  - `session invalid` — cookie present but signature didn't verify
    (wrong secret, tampered token, malformed JWT).
  - `session expired` — cookie present, signature OK, but `exp`
    claim is in the past.

## Likely cause

1. **User isn't logged in.** Browsing to an authenticated page
   (`/v1/customer/*`) without first hitting magic-link verify.
   Front-end should redirect to `/login`.
2. **Cookie domain mismatch.** Cookie was set with
   `Domain=.spize.io` but the user is calling from `localhost` or
   a staging URL. The browser doesn't send it. Check
   `AEX_FRONTEND_BASE_URL` matches the actual frontend origin.
3. **Session secret rotation.** If `AEX_SESSION_SECRET` rotated on
   the server, every session in flight becomes invalid. Expected
   side-effect of break-glass rotation; users have to re-login.
4. **Session past 30-day lifetime.** Default TTL — the user must
   re-authenticate via magic link.

## Remediation

For users: hit the magic-link request endpoint, get a new email,
click the link, get a fresh session.

For ops:
- Confirm `AEX_SESSION_SECRET` is set on Fly:
  `fly secrets list -a aex-control-plane | grep SESSION`
- Confirm `AEX_FRONTEND_BASE_URL` matches the frontend origin
  exactly (including scheme + no trailing slash).

## Related

- `crates/aex-control-plane/src/session.rs`
- `crates/aex-control-plane/src/routes/customer/auth.rs::require_customer_session`
