# ADR-0009: BSL-1.1 → Apache-2.0 conversion Q4 2026, pre-AAIF submission

## Status

Accepted 2026-04-21.

## Context

`aex-control-plane` currently ships under Business Source License 1.1 with
a four-year conversion to Apache-2.0 on 2029-04-20. The BSL restriction
(no competing hosted service) is defensive against a well-funded entity
commoditizing our Fly.io deploy. But it also blocks acceptance into most
open-source governance bodies — Apache Foundation, Linux Foundation, AAIF —
which is where the protocol needs to live for long-term legitimacy.

## Decision

We will convert `aex-control-plane` from BSL-1.1 to Apache-2.0 in Q4 2026,
ahead of the Phase 4 AAIF / LF submission. The conversion is published as
a license change PR with a CHANGELOG callout; no wire or API changes go
with it.

## Consequences

- We voluntarily give up the BSL restriction three years earlier than the
  original 2029 auto-conversion date.
- In exchange, the control plane becomes freely re-hostable by anyone —
  including competitors. Our moat stops being "license" and becomes
  "hosted operational quality + network effects + compliance bundle".
- The Phase 4 foundation submission (ADR-0037 scope) becomes viable.
- Existing customers on BSL-licensed builds get an automatic relicensing
  to Apache with no action required.
