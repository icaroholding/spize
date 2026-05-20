# @aexproto/sdk

TypeScript SDK for the **[Agent Exchange Protocol (AEX)](https://github.com/icaroholding/aex)** — an open, federated, identity-first protocol for cryptographically verifiable file transfer between autonomous agents.

The SDK ships byte-for-byte parity with the Rust reference implementation (`aex-core`) and the Python SDK (`aex-sdk`) for both wire v1 and wire v2. Cross-language byte equality is enforced by a shared golden-vector test suite that runs in every language's CI.

Requires Node ≥ 18 (uses global `fetch`). Works with Bun and Deno.

## Install

```sh
npm install @aexproto/sdk
```

## Quick start — `did:key` (zero infrastructure)

The simplest path: two agents generate self-certifying `did:key` identities locally, no registry needed.

```ts
import { Identity, SpizeClient } from "@aexproto/sdk";

// One-time: generate a local Ed25519 identity. The agent_id is
// derived from the public key (did:key:z6Mk...). Persist the
// private key somewhere safe (OS keychain, HSM, encrypted file).
const alice = await Identity.generate({ org: "alice-corp", name: "laptop" });

const client = new SpizeClient({
  baseUrl: "http://localhost:8080",
  identity: alice,
});
await client.register();

// Send a file to another agent.
const tx = await client.send({
  recipient: "did:web:bob-corp.com#agent",
  data: new TextEncoder().encode("Hello Bob"),
  declaredMime: "text/plain",
  filename: "note.txt",
});
console.log(tx.state);
```

## Wire v2 (recommended for new code)

Wire v2 messages are canonical, brand-neutral byte sequences with the `aex-*:v2` prefix. Identifiers follow the W3C DID URI grammar (`did:method:id[#fragment]`). Helpers are exported from the package root:

```ts
import {
  registrationChallengeBytesV2,
  transferIntentBytesV2,
  decisionRequestBytesV2,
  decisionResponseBytesV2,
} from "@aexproto/sdk";

const payload = transferIntentBytesV2({
  senderAgentId: "did:web:alice-corp.com#agent",
  recipient: "did:web:bob-corp.com#agent",
  sizeBytes: 12_345,
  declaredMime: "application/pdf",
  filename: "invoice.pdf",
  nonce: "0123456789abcdef0123456789abcdef",
  issuedAtUnix: 1_716_200_000,
});
```

## What the SDK gives you

- **`Identity`** — Ed25519 keypair generation, secret roundtrip, BIP-39 mnemonic recovery codes.
- **`SpizeClient`** — HTTP client that handles wire signing, replay nonces, capability negotiation, and transfer state.
- **Wire functions** — `registrationChallengeBytes` / `transferIntentBytes` / `transferReceiptBytes` / `rotateKeyChallengeBytes` for v1, and their `*V2` counterparts for v2. Mirror the Rust `aex-core` bytes exactly.
- **Retry + resolver helpers** — `RetryPolicy.normative()` matches `docs/protocol-v1.md` §5.1; DoH transport bypasses captive resolvers; captive-portal classifier.
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
