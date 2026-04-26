//! Transactional email delivery via Resend (Sprint 4 PR 7).
//!
//! The control plane stays provider-agnostic at the call site by
//! exposing a single [`send_magic_link`] entry point. The current
//! provider is Resend's REST API; swapping providers later means
//! changing only this module.
//!
//! # Why no SDK
//!
//! Resend's Rust SDK is thin and adds another supply-chain hop.
//! Its public API is "POST /emails with a JSON body and a Bearer
//! token" — we already have `reqwest` and `serde_json` for that.
//! Rolling the call by hand keeps the dependency surface small
//! and matches the rest of the control plane's tactical style.
//!
//! # Tagging
//!
//! Every email carries `tags: [{name: "app", value: "aex"},
//! {name: "type", value: "magic-link"}]` so that a Resend account
//! shared across multiple Bouncyloop projects can be filtered to
//! AEX-only events in the dashboard.

use serde::Serialize;

use crate::config::EmailConfig;

const RESEND_ENDPOINT: &str = "https://api.resend.com/emails";

/// Errors the email path can surface to the caller. Kept narrow
/// because the magic-link handler treats all of these as "drop the
/// email but accept the request" — the user must not be able to
/// distinguish "we tried and failed" from "we accepted but the
/// recipient isn't a customer" (privacy).
#[derive(Debug, thiserror::Error)]
pub enum EmailError {
    #[error("email provider not configured")]
    NotConfigured,
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("provider returned {status}: {body}")]
    Provider {
        status: reqwest::StatusCode,
        body: String,
    },
}

/// What the call site needs to render a magic-link email body.
/// Kept tiny so a future template engine swap (mjml, lettre, etc.)
/// is local to this module.
#[derive(Debug, Clone)]
pub struct MagicLinkEmail<'a> {
    pub to: &'a str,
    pub link: &'a str,
    /// Time the link is valid for, as a human-readable string —
    /// e.g. "15 minutes". The handler picks the value off the
    /// configured TTL so the email and the actual lifetime stay in
    /// sync.
    pub expires_in: &'a str,
}

/// POST a magic-link email through Resend. Returns `Ok(())` on a
/// 2xx response; any non-2xx is a [`EmailError::Provider`] with the
/// upstream body so operators can grep `fly logs` for the cause.
pub async fn send_magic_link(
    cfg: &EmailConfig,
    msg: &MagicLinkEmail<'_>,
) -> Result<(), EmailError> {
    let api_key = cfg
        .resend_api_key
        .as_deref()
        .ok_or(EmailError::NotConfigured)?;

    let body = ResendPayload {
        from: &cfg.mail_from,
        to: [msg.to],
        subject: "Sign in to Spize",
        html: &render_html(msg),
        text: &render_text(msg),
        tags: [
            ResendTag {
                name: "app",
                value: "aex",
            },
            ResendTag {
                name: "type",
                value: "magic-link",
            },
        ],
    };

    let client = reqwest::Client::new();
    let resp = client
        .post(RESEND_ENDPOINT)
        .bearer_auth(api_key)
        .json(&body)
        .send()
        .await?;

    let status = resp.status();
    if !status.is_success() {
        let upstream = resp
            .text()
            .await
            .unwrap_or_else(|_| "<could not read upstream body>".into());
        return Err(EmailError::Provider {
            status,
            body: upstream,
        });
    }
    Ok(())
}

/// Plain-text fallback for clients that don't render HTML.
fn render_text(msg: &MagicLinkEmail<'_>) -> String {
    format!(
        "Sign in to Spize\n\n\
         Click the link below to sign in:\n\n\
         {link}\n\n\
         This link expires in {expires_in}.\n\n\
         If you didn't request this, you can ignore this email.\n",
        link = msg.link,
        expires_in = msg.expires_in
    )
}

/// Minimal HTML body. Kept inline so the email module has no
/// template-file dependency. If we grow brand styling later, this
/// is the single place to swap in a richer renderer.
fn render_html(msg: &MagicLinkEmail<'_>) -> String {
    let MagicLinkEmail {
        link, expires_in, ..
    } = msg;
    let escaped_link = html_escape(link);
    let escaped_expiry = html_escape(expires_in);
    format!(
        r#"<!DOCTYPE html>
<html>
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;line-height:1.5;color:#1a1a1a;max-width:560px;margin:40px auto;padding:0 20px;">
  <h1 style="font-size:20px;margin-bottom:24px;">Sign in to Spize</h1>
  <p>Click the button below to sign in:</p>
  <p style="margin:32px 0;">
    <a href="{escaped_link}"
       style="background:#1a1a1a;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;">
      Sign in
    </a>
  </p>
  <p style="color:#666;font-size:14px;">
    Or copy this link into your browser:<br>
    <code style="font-size:12px;word-break:break-all;">{escaped_link}</code>
  </p>
  <p style="color:#666;font-size:14px;">This link expires in {escaped_expiry}.</p>
  <p style="color:#999;font-size:12px;margin-top:32px;">
    If you didn't request this, you can ignore this email.
  </p>
</body>
</html>"#,
    )
}

/// Tiny HTML escaper. We accept &amp; / &lt; / &gt; / &quot; — the
/// only characters that can break out of an attribute or element
/// body in our tightly-controlled template above. We do NOT need
/// full Unicode-aware escaping because the inputs are URL strings
/// and a TTL label, both of which are ASCII-safe by construction.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Serialize)]
struct ResendPayload<'a> {
    from: &'a str,
    to: [&'a str; 1],
    subject: &'a str,
    html: &'a str,
    text: &'a str,
    tags: [ResendTag<'a>; 2],
}

#[derive(Serialize)]
struct ResendTag<'a> {
    name: &'a str,
    value: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_body_includes_link_and_ttl() {
        let msg = MagicLinkEmail {
            to: "user@example.com",
            link: "https://spize.io/auth/callback?token=abc",
            expires_in: "15 minutes",
        };
        let body = render_text(&msg);
        assert!(body.contains("https://spize.io/auth/callback?token=abc"));
        assert!(body.contains("15 minutes"));
    }

    #[test]
    fn html_body_escapes_link() {
        let msg = MagicLinkEmail {
            to: "x@y.z",
            // A pathological link containing characters that must be
            // escaped in HTML attributes.
            link: r#"https://x.y/z?a=1&b=<script>"#,
            expires_in: "15 minutes",
        };
        let body = render_html(&msg);
        assert!(body.contains("&amp;b=&lt;script&gt;"));
        assert!(!body.contains("&b=<script>"));
    }

    #[test]
    fn send_returns_not_configured_when_key_missing() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let cfg = EmailConfig {
            resend_api_key: None,
            mail_from: "noreply@spize.io".into(),
        };
        let msg = MagicLinkEmail {
            to: "u@e.com",
            link: "https://x/",
            expires_in: "15m",
        };
        let err = rt
            .block_on(send_magic_link(&cfg, &msg))
            .expect_err("must fail when not configured");
        assert!(matches!(err, EmailError::NotConfigured));
    }
}
