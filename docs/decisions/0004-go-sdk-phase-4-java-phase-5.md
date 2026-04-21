# ADR-0004: Go SDK in Phase 4, Java SDK in Phase 5

## Status

Accepted 2026-04-21.

## Context

Python and TypeScript cover the overwhelming majority of agent ecosystems
today (LangChain, Agents SDK, Claude Desktop, MCP hosts). Go shows up in
infra-adjacent agents (LangGraph workers, Kubernetes operators, serverless
orchestrators) that are growing fast. Java matters for enterprise
integrations but is a slower-moving audience and risks costing SDK effort
that's better spent elsewhere until enterprise demand validates it.

## Decision

We will ship an official Go SDK in Phase 4 (Q4 2026) and a Java SDK in
Phase 5 (Q1 2027), in that order. No work on either before Phase 4.

## Consequences

- Python + TypeScript remain the Y1 SDK surface; every wire-format change
  (v1.3.0-beta.1, key rotation, JWS cards) lands there first.
- Go SDK timing aligns with Phase 4 ecosystem work (framework adapters,
  GitHub MCP registry join).
- Java SDK arrives when enterprise Helm chart lands, preventing a half-built
  Java story while there's no enterprise deploy to target.
- Third-party Go/Java SDKs may surface before ours; we will document the
  wire format well enough to make that easy and not attempt to block them.
