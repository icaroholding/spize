import { describe, expect, it } from "vitest";
import { needsDoh } from "../src/resolver.js";

describe("needsDoh", () => {
  const cases: [string, boolean][] = [
    ["https://example.com/", true],
    ["https://foo.trycloudflare.com/blob/x", true],
    ["http://example.com/", false],
    ["https://localhost:8080/", false],
    ["https://127.0.0.1/", false],
    ["https://1.2.3.4/", false],
    ["https://[::1]/", false],
    ["https://[2606:4700:4700::1111]/", false],
  ];

  for (const [url, expected] of cases) {
    it(`${url} → ${expected}`, () => {
      expect(needsDoh(new URL(url))).toBe(expected);
    });
  }
});
