# ADR-0030: `aex-net` crate scope — DNS + HTTP + retry + captive, nothing else

## Status

Accepted 2026-04-21.

## Context

Sprint 1 discovered four different DNS / network quirks in the field
(search-domain suffix, macOS NXDOMAIN cache, UDP/53 interception, DoH
fallback). The fix patterns want to live somewhere shared. A new
`aex-net` crate is the obvious home — but "shared network utilities"
is a magnet for scope creep that could swallow tunnel orchestration,
wire format helpers, retry-policy-for-business-logic, and more.

## Decision

`aex-net` is strictly: **DNS resolver + HTTP client factory + retry
policy + captive-portal detection.** Nothing else goes in. Transport
abstraction stays in `aex-tunnel`, wire format in `aex-core`, and
anything domain-specific in its own crate. The bounded scope is part
of the crate's identity.

## Consequences

- `aex-net` stays small, auditable, and easy to reason about.
- Adding a tempting-looking utility requires proving it isn't one of
  the bounded four and finding / making a better home.
- The four modules are each importable independently; a future
  `aex-net` re-export from an SDK doesn't drag the whole surface.
- Sprint 1.5's plan-eng-review (2026-04-21) reiterated the bound
  during crate-creation review.
