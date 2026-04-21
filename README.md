# AEX — Agent Exchange Protocol

[![CI](https://github.com/icaroholding/aex/actions/workflows/ci.yml/badge.svg)](https://github.com/icaroholding/aex/actions)
[![crates.io](https://img.shields.io/crates/v/aex-core.svg)](https://crates.io/crates/aex-core)
[![npm](https://img.shields.io/npm/v/@aexproto/sdk.svg)](https://www.npmjs.com/package/@aexproto/sdk)
[![PyPI](https://img.shields.io/pypi/v/aex-sdk.svg)](https://pypi.org/project/aex-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0%20%2B%20BSL--1.1-blue.svg)](#licensing)

**The open protocol for agent-to-agent file transfer.** Cryptographic identity, pluggable scanning, signed audit, pluggable policy.

> **Status:** `v1.2.0-alpha` — the protocol + reference implementation + SDKs are stable enough to build against. Wire format is frozen for the 1.x line. See [changelog](CHANGELOG.md) for what's ready vs planned.

AEX is the **Agent Exchange Protocol**. Spize is the company that authors it and will operate a reference hosted registry. The protocol, SDKs, and reference implementation are open source — the hosted service is planned.

## What AEX gives an agent

- **Verifiable identity.** Every transfer is signed with the sender's Ed25519 key. Recipients cryptographically verify origin before accepting bytes.
- **Canonical addressing.** Agents have stable IDs of the form `spize:org/name:fingerprint`, cryptographically bound to their public key. Senders don't need to know where the recipient's agent physically runs.
- **Content scanning.** Files flow through a pluggable pipeline (size, MIME, EICAR, regex-based prompt-injection detection) before the recipient ever sees them. Custom scanners plug in via a simple trait.
- **Org-wide policy.** Pre-send and post-scan policy hooks enforced by the protocol, not per-app.
- **Tamper-evident audit.** Every send, scan, accept, and ack is chained in a local Merkle log. Optional Rekor anchoring for public transparency.
- **Peer-to-peer data plane.** The control plane issues short-lived signed tickets (M2, `v1.2.0-alpha.2`+). Bytes stream from the sender's data plane directly — they don't transit the control plane.

## Quick start — two Python agents exchange a file

```bash
# 1. Start a local control plane
docker compose -f deploy/docker-compose.dev.yml up -d
DATABASE_URL=postgres://aex:aex_dev@localhost:5432/aex \
  cargo run -p aex-control-plane

# 2. In a second terminal: install the SDK + run the demo
cd packages/sdk-python
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python examples/demo_two_agents.py
```

The demo:
1. Generates two Ed25519 identities (Alice and Bob), registers them with proof-of-possession.
2. Alice signs an intent and sends a clean file → scanner passes → Bob downloads and acks.
3. Alice tries to send the EICAR test string → scanner blocks → transfer rejected → audit chain records the rejection.

Full walkthrough: [`docs/getting-started.md`](docs/getting-started.md).

## Architecture

```
┌──────────────┐        control plane         ┌──────────────┐
│  Agent A     │  ─── register, intent  ──►   │ aex-control- │
│  (Alice)     │  ◄── ticket, audit head ──   │    plane     │
└──────┬───────┘                              └──────┬───────┘
       │                                             │
       │       tunnel handshake + ticket             │
       ▼                                             ▼
┌──────────────┐        data plane          ┌──────────────┐
│  aex-data-   │  ─────── blob ──────────►  │  Agent B     │
│  plane       │                            │  (Bob)       │
│  (on Alice)  │  ◄─ signed receipt ──────  │              │
└──────────────┘                            └──────────────┘
```

- **Control plane** (`aex-control-plane`, BSL-1.1): registry + ticket issuance + audit anchor. Metadata only — with M2 enabled, never sees the bytes.
- **Data plane** (`aex-data-plane`, Apache-2.0): sender-side HTTP server exposing a blob by signed ticket. Cloudflare tunnel for NAT traversal.
- **SDKs** (`aex-sdk` Python, `@aexproto/sdk` TypeScript, `@aexproto/mcp-server` for LLM hosts): wrap the wire format + transfer flow.

Deep dive: [`docs/architecture.md`](docs/architecture.md). Wire format spec: [`docs/protocol-v1.md`](docs/protocol-v1.md).

## Why

Autonomous agents increasingly need to exchange files — PDFs, datasets, generated reports — across organizations. Today they improvise over Gmail, Slack, Drive, S3 pre-signed URLs. None of those were designed for agents:

- **No verifiable origin.** A Claude pretending to be a Claude from the accounting firm can just lie.
- **Surveillance posture.** Every file passes through a human-oriented intermediary with full content visibility.
- **Brittle policy.** Compliance is a per-integration toolkit, re-implemented at every company.
- **No audit.** When a legal issue arises, "I swear the file arrived at 14:32" doesn't hold up.

AEX is the file-transfer layer agents should have had from day one.

## Hosted registry (planned)

We plan to operate a reference hosted registry at **spize.io** so teams can adopt AEX without running their own control plane. Pricing, free tier details, and SLA will be published when the service enters public beta. Until then, running your own control plane is the path — see the Quick start above.

Self-hosting vs the future hosted service will be a classic trade-off of operational convenience vs data control. Both are first-class citizens of the protocol.

## Repository structure

```
crates/
  aex-core          — shared types, wire formats, errors
  aex-identity      — Ed25519 + EtereCitizen DID providers
  aex-audit         — local Merkle chain + optional Rekor anchor
  aex-scanner       — size / MIME / EICAR / regex pipeline
  aex-policy        — pre-send and post-scan policy traits
  aex-tunnel        — Cloudflare tunnel orchestration
  aex-billing       — billing provider trait (skeleton)
  aex-data-plane    — peer-to-peer blob server
  aex-control-plane — registry + ticket issuer + audit anchor (BSL-1.1)
packages/
  sdk-python        — aex-sdk on PyPI
  sdk-typescript    — @aexproto/sdk on npm
  mcp-server        — @aexproto/mcp-server on npm (Claude Desktop / Cursor integration)
web/                — landing + operator dashboard + download UI
deploy/             — docker-compose for local dev; production deploy recipes planned
docs/               — architecture, protocol spec, getting started
```

## Contributing

We use the [Developer Certificate of Origin](https://developercertificate.org) for contributions. Sign your commits with `git commit -s`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the dev loop, test requirements, and code style.

For security reports, see [SECURITY.md](SECURITY.md).

## Licensing

- Protocol specs, all crates except one, all SDKs, and the web code: **Apache License 2.0** — [`LICENSE`](LICENSE).
- `aex-control-plane`: **Business Source License 1.1** — [`LICENSE.bsl`](LICENSE.bsl). Converts to Apache-2.0 on **2029-04-20**.

The BSL grant allows any production use except offering `aex-control-plane` as a hosted service competing with Spize's planned offering. For anything else — internal deployment, self-hosting, modification, derivative work — there is no restriction.

## Related projects

- [EtereCitizen](https://github.com/icaroholding/EtereCitizen) — the DID-based identity provider AEX consumes via `aex-identity`.

---

Built by [Icaro Holding](https://icaro.ai).
