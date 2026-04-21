# ADR-0007: Free beta Jun–Sep 2026; paid tier Sep 2026; grandfather first 50 users

## Status

Accepted 2026-04-21.

## Context

AEX wants adoption velocity (the MCP / A2A ecosystem window is 6–12 months
wide) AND revenue by Y1 Q3 (self-funded; see ADR-0010). Those tensions
resolve if the protocol is free while we close the product gaps and paid as
soon as it's ready. Early adopters earn something for trusting us pre-
revenue.

## Decision

The hosted service at `api.spize.io` is free from its launch (Phase 1 end)
through September 2026. On 2026-09-01 we introduce paid tiers; the first
50 accounts in Jun–Sep 2026 are grandfathered at $29/month for life on the
Dev Pro plan. New signups after the cutoff pay list price.

## Consequences

- There's a real deadline (Sep 2026) the roadmap has to hit — Stripe
  integration, API-key management, usage dashboard all must be production
  in Phase 1 Sprint 4.
- Grandfather pool is capped: after 50, no more lifetime pricing. This
  needs enforcement in the signup flow.
- Early-adopter goodwill (50 lifetime seats) is a finite marketing asset;
  spend it deliberately on high-signal accounts.
- Free-tier usage metrics are the evidence that supports Q3 pricing
  decisions — instrument them before Jun.
