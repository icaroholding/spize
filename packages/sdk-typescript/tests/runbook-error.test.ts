import { describe, expect, it } from "vitest";

import { Identity } from "../src/identity.js";
import { SpizeClient } from "../src/client.js";
import { SpizeHttpError } from "../src/errors.js";

describe("SpizeHttpError runbookUrl", () => {
  it("surfaces the server's runbook_url field onto the exception", async () => {
    const alice = await Identity.generate({ org: "acme", name: "alice" });
    const runbook =
      "https://github.com/icaroholding/aex/blob/master/docs/runbooks/signature-invalid.md";

    const mockFetch: typeof globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          code: "unauthorized",
          message: "signature does not match challenge",
          runbook_url: runbook,
        }),
        { status: 401, headers: { "content-type": "application/json" } },
      );

    const client = new SpizeClient({
      baseUrl: "http://test",
      identity: alice,
      fetch: mockFetch,
    });

    await expect(client.register()).rejects.toSatisfy((err) => {
      const e = err as SpizeHttpError;
      expect(e.statusCode).toBe(401);
      expect(e.code).toBe("unauthorized");
      expect(e.runbookUrl).toBe(runbook);
      expect(e.message).toContain(runbook); // message string contains the URL
      return true;
    });
  });

  it("tolerates missing runbook_url from older servers", async () => {
    const alice = await Identity.generate({ org: "acme", name: "alice" });

    const mockFetch: typeof globalThis.fetch = async () =>
      new Response(
        JSON.stringify({
          code: "conflict",
          message: "older-server conflict",
        }),
        { status: 409, headers: { "content-type": "application/json" } },
      );

    const client = new SpizeClient({
      baseUrl: "http://test",
      identity: alice,
      fetch: mockFetch,
    });

    await expect(client.register()).rejects.toSatisfy((err) => {
      const e = err as SpizeHttpError;
      expect(e.runbookUrl).toBeNull();
      return true;
    });
  });

  it("exposes runbookUrl as readonly on the constructor surface", () => {
    const err = new SpizeHttpError(
      500,
      "internal_error",
      "internal server error",
      "https://example/runbooks/internal-error.md",
    );
    expect(err.runbookUrl).toBe(
      "https://example/runbooks/internal-error.md",
    );
    // Default value when omitted.
    const plain = new SpizeHttpError(500, "internal_error", "oops");
    expect(plain.runbookUrl).toBeNull();
  });
});
