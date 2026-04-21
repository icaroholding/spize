# ADR-0005: Internal compliance framework; customer-funded audit; no Vanta Y1

## Status

Accepted 2026-04-21.

## Context

SOC2 Type 1 readiness typically costs $5–10k/year in tooling (Vanta, Drata)
plus the audit itself. Year 1 of AEX is self-funded (ADR-0010). Spending
$10k on compliance tooling before a single paying customer is a misaligned
bet; internal discipline (policies, access review, audit log, key
management) gets 80 % of the benefit for near-zero marginal cost.

## Decision

We will maintain an internal compliance framework (policies checked into
the repo, quarterly access review, audit-log export tooling) and will fund
an external SOC2 audit only when a customer asks for it and contributes to
the cost. Vanta / Drata subscriptions are not purchased in Y1.

## Consequences

- Enterprise sales cycles that demand pre-existing SOC2 Type 1 are
  deferred until Phase 5, when the audit is funded.
- The internal framework doubles as contributor-onboarding documentation
  (ADR-0037).
- We lose some discovery advantage in vendor compliance directories
  (Vanta Marketplace). Acceptable — direct sales are Y1's path.
- When we do procure an audit it will be a traditional engagement, not a
  SaaS compliance workflow. Budget $15–30k single-shot.
