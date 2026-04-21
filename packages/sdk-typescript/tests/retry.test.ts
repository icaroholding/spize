import { describe, expect, it } from "vitest";
import { RetryPolicy, retryWithBackoff } from "../src/retry.js";

// Zero-delay policy so tests don't actually sleep between retries.
// We verify the backoff curve separately in the RetryPolicy block.
const FAST_POLICY: RetryPolicy = {
  maxAttempts: 3,
  baseDelayMs: 0,
  multiplier: 1,
  jitterMs: 0,
};

describe("RetryPolicy", () => {
  it("normative matches protocol-v1 §5.1", () => {
    const p = RetryPolicy.normative();
    expect(p.maxAttempts).toBe(3);
    expect(p.baseDelayMs).toBe(1000);
    expect(p.multiplier).toBe(2);
    expect(p.jitterMs).toBe(100);
  });

  it("first attempt has zero backoff", () => {
    const p = RetryPolicy.normative();
    expect(RetryPolicy.backoffForAttemptMs(p, 1)).toBe(0);
    expect(RetryPolicy.backoffForAttemptMs(p, 0)).toBe(0);
  });

  it("second attempt jitter is bounded", () => {
    const p = RetryPolicy.normative();
    for (let i = 0; i < 500; i++) {
      const d = RetryPolicy.backoffForAttemptMs(p, 2);
      expect(d).toBeGreaterThanOrEqual(900);
      expect(d).toBeLessThanOrEqual(1100);
    }
  });

  it("third attempt doubles base", () => {
    const p = RetryPolicy.normative();
    for (let i = 0; i < 500; i++) {
      const d = RetryPolicy.backoffForAttemptMs(p, 3);
      expect(d).toBeGreaterThanOrEqual(1900);
      expect(d).toBeLessThanOrEqual(2100);
    }
  });
});

describe("retryWithBackoff", () => {
  it("succeeds on first attempt", async () => {
    let calls = 0;
    const result = await retryWithBackoff(
      FAST_POLICY,
      () => true,
      async () => {
        calls++;
        return 42;
      },
    );
    expect(result).toBe(42);
    expect(calls).toBe(1);
  });

  it("succeeds after two transient failures", async () => {
    let calls = 0;
    const result = await retryWithBackoff(
      FAST_POLICY,
      () => true,
      async () => {
        calls++;
        if (calls < 3) throw new Error("transient");
        return 7;
      },
    );
    expect(result).toBe(7);
    expect(calls).toBe(3);
  });

  it("rejects with last error on exhaustion", async () => {
    let calls = 0;
    await expect(
      retryWithBackoff(FAST_POLICY, () => true, async () => {
        calls++;
        throw new Error(`fail ${calls}`);
      }),
    ).rejects.toThrow("fail 3");
    expect(calls).toBe(3);
  });

  it("non-retriable error short-circuits", async () => {
    let calls = 0;
    class PermanentError extends Error {}
    await expect(
      retryWithBackoff(
        FAST_POLICY,
        (err) => !(err instanceof PermanentError),
        async () => {
          calls++;
          throw new PermanentError("nope");
        },
      ),
    ).rejects.toBeInstanceOf(PermanentError);
    expect(calls).toBe(1);
  });

  it("rejects invalid maxAttempts", async () => {
    const badPolicy: RetryPolicy = {
      maxAttempts: 0,
      baseDelayMs: 1000,
      multiplier: 2,
      jitterMs: 100,
    };
    await expect(
      retryWithBackoff(badPolicy, () => true, async () => 42),
    ).rejects.toThrow("maxAttempts must be");
  });
});
