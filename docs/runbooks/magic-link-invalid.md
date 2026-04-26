# Runbook: magic link invalid / expired / already used

## Symptom

- **Status:** `401 Unauthorized`
- **`code`:** `unauthorized`
- **Message:** one of:
  - `magic link not recognized` — the token doesn't match any row.
  - `magic link expired` — token exists but is past its 15-minute window.
  - `magic link already used` — token was already redeemed once
    (single-use invariant).

## Likely cause

1. **Old or stale link.** The user clicked a link from an email
   that's older than 15 minutes. Magic links expire fast on purpose
   — they're a credential-equivalent in transit.
2. **Already used.** The user (or a tab somewhere) clicked the link,
   then clicked again. Magic links are single-use; the first click
   sets a session, subsequent clicks fail.
3. **Tampered URL.** Mid-paste truncation, mail client URL-rewriting
   (Gmail link checker, Outlook Safe Links). The token in the URL
   no longer matches what the server stored.

## Remediation

Tell the user to request a new magic link from the dashboard
sign-in page. The previous one is gone (single-use). New link =
new 15-minute window.

If a user reports this consistently within minutes of receiving the
email, suspect URL rewriting from their email provider — check the
"Show original" view in their inbox to see whether the URL changed
between Resend's send and their click.

## Related

- `crates/aex-control-plane/src/db/magic_link_tokens.rs::consume`
- `crates/aex-control-plane/src/routes/customer/auth.rs::magic_link_verify`
