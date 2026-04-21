# ADR-0017: Captive-portal detection in a shared crate; multi-endpoint consensus; soft-warn

## Status

Accepted 2026-04-21.

## Context

Captive portals silently break HTTPS to unrelated hosts (they return login
pages from other origins). Detecting this state once, in one place, and
emitting an advisory signal lets every AEX binary and SDK surface it
without each re-implementing the logic. Hard-failing on captive portal
would be wrong — plenty of captive networks let whitelist traffic through,
including the portal's own cloud providers. Soft-warn is the right default.

## Decision

Captive-portal detection lives in the shared `aex-net` crate and is
mirrored in the Python SDK (`aex_sdk.captive`) and TypeScript SDK
(`@aexproto/sdk` → `captive.ts`). Detection probes three canonical
endpoints (Apple `/hotspot-detect.html`, Google `/generate_204`,
Microsoft `/ncsi.txt`) and reports the consensus as `NetworkState`
(`direct` / `captive_portal` / `limited` / `unknown`). The data-plane
binary emits `AEX_NETWORK_STATE=<state>` on stdout at startup (ADR-0030
Delight #5). No AEX code paths block or fail based on the state.

## Consequences

- Users behind a captive portal get an advisory line in their orchestrator
  stdout; they can surface it to the human operator.
- Protocol behaviour is unchanged — a captive-portal environment either
  transits transfers successfully or fails naturally at connect time.
- Normative grammar for the probe responses is pinned in
  `docs/protocol-v1.md` §5.3 so the three SDKs stay aligned.
