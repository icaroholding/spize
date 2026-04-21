# ADR-0023: Captive-portal rescue — rich error with actionable hint

## Status

Accepted 2026-04-21.

## Context

When a user tries to transfer from a coffee-shop wifi that hasn't been
accepted yet, today they get an opaque "tunnel unreachable" error. The
captive-portal detector (ADR-0017) already knows the network state. We
can thread that knowledge into the error so the message is actionable
instead of cryptic (Delight #3).

## Decision

When a transfer fails and `NetworkState::CaptivePortal` was the most
recent reading, errors surfaced from the SDK (`SpizeError` /
`SpizeHttpError`) carry an extra `rescue_hint` field with text like:

> "Your network appears to be behind a captive portal (detected via
> captive.apple.com). Open http://captive.apple.com in a browser to
> complete the portal login, then retry."

Orchestrators that surface `SpizeError.to_string()` to users get the
hint automatically; programmatic consumers can inspect the struct field.

## Consequences

- Better first-run UX on travel networks.
- No false positives blocking real transfers: the hint is attached only
  when detection actually fires.
- Rescue hints are localisable but ship English-only in v1.x; a i18n
  file lands in Phase 2.
- Error formatters in SDKs grow a couple of lines to render the hint.
