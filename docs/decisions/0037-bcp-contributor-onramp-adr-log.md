# ADR-0037: Business continuity plan + contributor onramp + ADR log

## Status

Accepted 2026-04-21.

## Context

AEX is a solo-founder protocol today. Three things protect against
single-point-of-failure (bus factor, legal attack, founder burnout):
a documented BCP with key escrow, a contributor onramp that lets a
second developer ship in <1 week, and this ADR log so past decisions
survive the person who made them.

## Decision

Three artefacts live in-repo, maintained continuously:

1. **BCP** (`docs/continuity.md`) — Bitwarden vault `aex-bcp-vault`,
   2-of-3 Shamir split among trusted contacts, legal instructions for
   handling the domain + brand if the founder is incapacitated.
2. **Contributor onramp** (`CONTRIBUTING.md`, already in-repo for DCO
   signing, expanded with dev-setup, architecture overview,
   first-PR walkthrough).
3. **ADR log** (this directory, `docs/decisions/`) — this ADR (0037) is
   itself the policy that every non-trivial architectural or strategic
   decision gets an ADR.

## Consequences

- BCP setup is Sprint 4 work (ADR-0003 timing), not deferred.
- Contributor onramp lands in Phase 4 when open-source posture
  justifies it.
- ADR log starts now with the 37 decisions from the 2026-04-21 plan
  review; subsequent decisions land as they happen.
- Nothing in the ADR log is ever rewritten retroactively — if a
  decision changes, a new ADR supersedes it (and both are kept).
