# @aexproto/sdk

TypeScript client for the [Agent Exchange Protocol (AEX)](https://github.com/icaroholding/aex).

## Install

```sh
npm install @aexproto/sdk
```

## Quick start

```ts
import { Identity, SpizeClient } from "@aexproto/sdk";

// One-time: create + register an identity.
const identity = await Identity.generate({ org: "acme", name: "alice" });
// Persist the raw secret somewhere safe (OS keychain, HSM, encrypted file).
// await fs.writeFile("alice.bin", identity.privateKey);

const client = new SpizeClient({ baseUrl: "http://localhost:8080", identity });
await client.register();

// Send.
const tx = await client.send({
  recipient: "spize:acme/bob:aabbcc",
  data: new TextEncoder().encode("Ciao Bob"),
  declaredMime: "text/plain",
  filename: "note.txt",
});
console.log(tx.state);

// Receive (as Bob).
const bob = Identity.fromSecret({ org: "acme", name: "bob", privateKey: loaded });
const bobClient = new SpizeClient({ baseUrl: "http://localhost:8080", identity: bob });
const bytes = await bobClient.download(tx.transferId);
await bobClient.ack(tx.transferId);
```

Requires Node 18+ (uses global `fetch`). Works in Bun and Deno.
