import { describe, expect, it } from "vitest";
import {
  APPLE_URL,
  GOOGLE_URL,
  MS_URL,
  consensus,
  detectNetworkState,
  networkStateToStdoutValue,
  type NetworkState,
} from "../src/captive.js";

describe("consensus", () => {
  it("all ok is direct", () => {
    expect(consensus(["ok", "ok", "ok"])).toBe("direct");
  });

  it("any captive wins", () => {
    expect(consensus(["ok", "captive", "ok"])).toBe("captive_portal");
  });

  it("all failed is unknown", () => {
    expect(consensus(["failed", "failed", "failed"])).toBe("unknown");
  });

  it("mixed ok and failed is limited", () => {
    expect(consensus(["ok", "failed", "failed"])).toBe("limited");
  });

  it("unexpected without captive is limited", () => {
    expect(consensus(["ok", "unexpected", "ok"])).toBe("limited");
  });
});

describe("networkStateToStdoutValue", () => {
  it("emits canonical lowercase tokens", () => {
    const cases: [NetworkState, string][] = [
      ["direct", "direct"],
      ["captive_portal", "captive_portal"],
      ["limited", "limited"],
      ["unknown", "unknown"],
    ];
    for (const [input, expected] of cases) {
      expect(networkStateToStdoutValue(input)).toBe(expected);
    }
  });
});

describe("detectNetworkState", () => {
  function mockFetch(
    handler: (url: string) => Response | Promise<Response>,
  ): typeof globalThis.fetch {
    return (async (input: RequestInfo | URL, _init?: RequestInit) => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      return handler(url);
    }) as typeof globalThis.fetch;
  }

  it("direct when all three probes healthy", async () => {
    const fetch = mockFetch((url) => {
      if (url === APPLE_URL) return new Response("<HTML>Success</HTML>");
      if (url === GOOGLE_URL) return new Response(null, { status: 204 });
      if (url === MS_URL) return new Response("Microsoft NCSI");
      return new Response(null, { status: 500 });
    });
    expect(await detectNetworkState({ fetch })).toBe("direct");
  });

  it("captive when apple returns login-ish body", async () => {
    const fetch = mockFetch((url) => {
      if (url === APPLE_URL) return new Response("Please sign in");
      if (url === GOOGLE_URL) return new Response(null, { status: 204 });
      return new Response("Microsoft NCSI");
    });
    expect(await detectNetworkState({ fetch })).toBe("captive_portal");
  });

  it("captive when apple redirects", async () => {
    const fetch = mockFetch((url) => {
      if (url === APPLE_URL)
        return new Response(null, { status: 302, headers: { location: "/login" } });
      if (url === GOOGLE_URL) return new Response(null, { status: 204 });
      return new Response("Microsoft NCSI");
    });
    expect(await detectNetworkState({ fetch })).toBe("captive_portal");
  });

  it("limited when google returns 200 instead of 204", async () => {
    const fetch = mockFetch((url) => {
      if (url === APPLE_URL) return new Response("Success");
      if (url === GOOGLE_URL) return new Response("intercepted");
      return new Response("Microsoft NCSI");
    });
    expect(await detectNetworkState({ fetch })).toBe("limited");
  });

  it("unknown when all probes fail", async () => {
    const fetch = mockFetch(() => {
      throw new Error("network down");
    });
    expect(await detectNetworkState({ fetch })).toBe("unknown");
  });
});
