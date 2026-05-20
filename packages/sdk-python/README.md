# aex-sdk

Python SDK for the **[Agent Exchange Protocol (AEX)](https://github.com/icaroholding/aex)** — an open, federated, identity-first protocol for cryptographically verifiable file transfer between autonomous agents.

The SDK ships byte-for-byte parity with the Rust reference implementation (`aex-core`) and the TypeScript SDK (`@aexproto/sdk`) for both wire v1 and wire v2. Cross-language byte equality is enforced by a shared golden-vector test suite that runs in every language's CI.

## Install

```sh
pip install aex-sdk
```

Requires Python ≥ 3.10.

## Quick start — `did:key` (zero infrastructure)

The simplest path: two agents generate self-certifying `did:key` identities locally, no registry needed.

```python
from aex_sdk import Identity, SpizeClient

# One-time: generate a local Ed25519 identity. The agent_id is
# derived from the public key (did:key:z6Mk...). Private key never
# leaves the process.
alice = Identity.generate(org="alice-corp", name="laptop")
alice.save("alice.key")

client = SpizeClient(base_url="http://localhost:8080", identity=alice)
client.register()

# Send a file to another agent.
transfer = client.send(
    recipient="did:web:bob-corp.com#agent",
    file="invoice.pdf",
    declared_mime="application/pdf",
)
print(transfer.state)  # 'ready_for_pickup' or 'rejected'
```

## Wire v2 (recommended for new code)

Wire v2 messages are canonical, brand-neutral byte sequences with the `aex-*:v2` prefix. Identifiers follow the W3C DID URI grammar (`did:method:id[#fragment]`). Helpers live in `aex_sdk.wire_v2`:

```python
from aex_sdk.wire_v2 import (
    registration_challenge_bytes_v2,
    transfer_intent_bytes_v2,
    decision_request_bytes_v2,
    decision_response_bytes_v2,
)

# Canonical bytes that the recipient verifies.
payload = transfer_intent_bytes_v2(
    sender_agent_id="did:web:alice-corp.com#agent",
    recipient="did:web:bob-corp.com#agent",
    size_bytes=12_345,
    declared_mime="application/pdf",
    filename="invoice.pdf",
    nonce="0123456789abcdef0123456789abcdef",
    issued_at_unix=1_716_200_000,
)
```

## What the SDK gives you

- **`Identity`** — Ed25519 keypair generation, save/load to disk, BIP-39 mnemonic recovery codes.
- **`SpizeClient`** — async HTTP client that handles wire signing, replay nonces, capability negotiation, and transfer state.
- **`wire`** (v1) and **`wire_v2`** — canonical byte functions. Mirror `aex-core::wire` and `aex-core::wire_v2` byte-for-byte.
- **Resolver + retry helpers** — DoH-backed DNS resolution (`CloudflareDoHResolver`), normative retry policy (`RetryPolicy.normative()` per `docs/protocol-v1.md` §5.1), captive-portal detection.
- **Endpoint negotiation** — multi-tunnel transport selection with health probes.

## Identity methods

The SDK can produce and verify identities in four DID methods:

| Method | Use case |
|---|---|
| `did:key:z6Mk…` | Offline / device-local, self-certifying |
| `did:web:acme.com#agent` | Domain-anchored via `/.well-known/agent-card.json` |
| `did:ethr:8453:0x…` | On-chain identity with reputation (EtereCitizen) |
| `did:spize:org/name#fp` | Hosted convenience (reference operator) |

Legacy `spize:org/name:fingerprint` identifiers continue to parse during the v1→v2 grace window.

## Documentation

- [Protocol specification (v2)](https://github.com/icaroholding/aex/blob/master/docs/protocol-v2.md)
- [Protocol specification (v1, legacy)](https://github.com/icaroholding/aex/blob/master/docs/protocol-v1.md)
- [Architecture overview](https://github.com/icaroholding/aex/blob/master/docs/architecture.md)
- [Architectural Decision Records](https://github.com/icaroholding/aex/tree/master/docs/decisions)
- [Conformance test suite](https://github.com/icaroholding/aex/tree/master/crates/aex-conformance)

## License

Apache-2.0. See `LICENSE` in the repository root.
