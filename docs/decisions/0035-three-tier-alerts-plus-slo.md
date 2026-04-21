# ADR-0035: 3-tier alerts (P1 page / P2 ticket / P3 info) + SLO + error budget

## Status

Accepted 2026-04-21.

## Context

Every unpaged alert is noise that trains the on-caller to ignore
alarms. Every unalerted incident is a quality failure. The middle
ground is a clear tier structure — only a small, curated set of
conditions pages a human; everything else tickets or logs. SLOs +
error budgets quantify when to slow down and pay down reliability
debt.

## Decision

Three alert tiers:

- **P1 — page (phone + SMS):** control plane 5xx rate >1% over 5 min;
  any 1xx or 5xx on `/v1/public-key` (identity root).
- **P2 — ticket (email):** `reachable_at[]` re-validation failure rate
  >5 % over 15 min; Rekor anchor failures; single-region DERP
  unreachable.
- **P3 — info (slack channel):** SLO budget under 50 %; chaos-test
  failures; version drift between deployed CP and latest tagged.

SLOs: `api.spize.io` 99.5 % monthly (P1 gate). Error budget
deliberately spent on ship-velocity Y1.

## Consequences

- Noise floor stays manageable for a solo founder on call 24/7.
- Clear escalation path the day we hire.
- Error-budget math gives a data-driven "slow down" signal when
  reliability suffers.
- SLOs documented in `docs/slo.md` when that file lands in Phase 1
  Sprint 3.
