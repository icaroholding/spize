# ADR-0006: DID:ethr minimal support in Phase 4; deeper integration only on adoption signal

## Status

Accepted 2026-04-21.

## Context

EtereCitizen (a sibling project by the same founder) is a DID+reputation
protocol on Base L2. It is the most credible future source of portable
agent reputation and commerce. But AEX's thesis is "compliance-grade
transfer substrate underneath MCP/A2A" — betting core adoption on Base
chain availability or a niche DID method is a distraction. We keep the
door open without making the bet.

## Decision

We will add minimal `did:ethr` support as an additional identity provider
in Phase 4 (Q4 2026), after the wire is stable and the core ecosystem
story lands. Deeper EtereCitizen integration (reputation-weighted routing,
on-chain audit anchoring, bridged attestations) happens only if the Phase 4
work surfaces an organic adoption signal.

## Consequences

- AEX remains fully usable without Ethereum L2 involvement.
- The `icaroholding/EtereCitizen` repo stays an optional premium provider
  via `aex-identity`, not a hard dependency.
- The L2 integration, when it happens, is a Phase 4+ commitment; no wire
  decisions in v1.x assume on-chain state.
- Founders advising in this space get a clear answer: "yes, there's a path
  to reputation — on signal, not on faith".
