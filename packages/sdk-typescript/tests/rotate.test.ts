import { describe, expect, it } from "vitest";

import { hex, Identity, verifySignature } from "../src/identity.js";
import { SpizeClient } from "../src/client.js";
import { SpizeError } from "../src/errors.js";
import { rotateKeyChallengeBytes } from "../src/wire.js";

async function twoAliceIdentities(): Promise<[Identity, Identity]> {
  const a = await Identity.generate({ org: "acme", name: "alice" });
  let b = await Identity.generate({ org: "acme", name: "alice" });
  // Defensive — on the astronomical chance of a collision on a
  // freshly-generated ed25519 keypair, regenerate until distinct.
  while (b.publicKeyHex === a.publicKeyHex) {
    b = await Identity.generate({ org: "acme", name: "alice" });
  }
  return [a, b];
}

describe("SpizeClient.rotateKey", () => {
  it("posts a correctly-signed challenge and parses the response", async () => {
    const [alice, aliceNew] = await twoAliceIdentities();
    let captured: Record<string, unknown> = {};

    const mockFetch: typeof globalThis.fetch = async (url, init) => {
      const u = url instanceof Request ? url.url : url.toString();
      expect(u).toMatch(/\/v1\/agents\/rotate-key$/);
      const body = JSON.parse((init!.body as string) ?? "{}");
      captured = body;

      // Re-derive canonical bytes using alice's CURRENT pubkey and
      // verify the signature. This is what the control plane does.
      const canonical = rotateKeyChallengeBytes({
        agentId: body.agent_id as string,
        oldPublicKeyHex: alice.publicKeyHex,
        newPublicKeyHex: body.new_public_key_hex as string,
        nonce: body.nonce as string,
        issuedAtUnix: body.issued_at as number,
      });
      const sig = hex.decode(body.signature_hex as string);
      const ok = await verifySignature(alice.publicKey, canonical, sig);
      expect(ok).toBe(true);

      const now = Math.floor(Date.now() / 1000);
      return new Response(
        JSON.stringify({
          agent_id: body.agent_id,
          new_public_key_hex: body.new_public_key_hex,
          valid_from: now,
          previous_key_valid_until: now + 24 * 60 * 60,
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const client = new SpizeClient({
      baseUrl: "http://test",
      identity: alice,
      fetch: mockFetch,
    });
    const resp = await client.rotateKey(aliceNew);

    expect(resp.newPublicKeyHex).toBe(aliceNew.publicKeyHex);
    expect(resp.previousKeyValidUntil - resp.validFrom).toBe(24 * 60 * 60);
    expect(captured.agent_id).toBe(alice.agentId);
    expect(captured.new_public_key_hex).toBe(aliceNew.publicKeyHex);
  });

  it("refuses to rotate across org/name", async () => {
    const alice = await Identity.generate({ org: "acme", name: "alice" });
    const mallory = await Identity.generate({ org: "acme", name: "mallory" });

    const mockFetch: typeof globalThis.fetch = async () => {
      throw new Error("client must refuse before hitting the network");
    };
    const client = new SpizeClient({
      baseUrl: "http://test",
      identity: alice,
      fetch: mockFetch,
    });

    await expect(client.rotateKey(mallory)).rejects.toBeInstanceOf(SpizeError);
  });

  it("refuses to rotate to an identical key", async () => {
    const alice = await Identity.generate({ org: "acme", name: "alice" });

    const mockFetch: typeof globalThis.fetch = async () => {
      throw new Error("client must refuse before hitting the network");
    };
    const client = new SpizeClient({
      baseUrl: "http://test",
      identity: alice,
      fetch: mockFetch,
    });

    await expect(client.rotateKey(alice)).rejects.toBeInstanceOf(SpizeError);
  });
});
