/**
 * Exponential-backoff retry helpers. TypeScript mirror of the Rust
 * `aex-net::retry` module and the Python `aex_sdk.retry` module.
 *
 * See `docs/protocol-v1.md` §5.1 for the normative spec. The values in
 * {@link RetryPolicy.normative} are pinned to that spec and must stay in
 * sync with the Rust and Python sibling implementations.
 */

/** Exponential-backoff retry policy with bounded jitter. */
export interface RetryPolicy {
  /** Maximum attempts including the first. Must be ≥ 1. */
  maxAttempts: number;
  /** Base delay in milliseconds for the first retry. */
  baseDelayMs: number;
  /** Multiplier applied between successive retries. */
  multiplier: number;
  /** Absolute jitter (milliseconds) sampled uniformly in [-jitter, +jitter]. */
  jitterMs: number;
}

export const RetryPolicy = {
  /**
   * AEX normative retry policy per protocol-v1 §5.1.
   *
   * 3 attempts, 1000 ms base, 2× multiplier, ±100 ms jitter.
   */
  normative(): RetryPolicy {
    return {
      maxAttempts: 3,
      baseDelayMs: 1000,
      multiplier: 2,
      jitterMs: 100,
    };
  },

  /**
   * Milliseconds to sleep *before* attempt `n` (1-indexed).
   * For `n ≤ 1` returns 0 — the first attempt runs immediately.
   */
  backoffForAttemptMs(policy: RetryPolicy, attempt: number): number {
    if (attempt <= 1) return 0;
    const exp = attempt - 2;
    const base = policy.baseDelayMs * Math.pow(policy.multiplier, exp);
    const j =
      policy.jitterMs > 0
        ? (Math.random() * 2 - 1) * policy.jitterMs
        : 0;
    return Math.max(0, base + j);
  },
};

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Run an async operation with bounded retry on rejection.
 *
 * - `policy` controls max attempts and backoff curve.
 * - `shouldRetry` inspects each caught error and returns whether the
 *   failure is transient and worth retrying. Return `false` to short-
 *   circuit on non-retriable failures (e.g. invalid ticket).
 * - `op` is the async operation. It is re-invoked once per retry.
 */
export async function retryWithBackoff<T>(
  policy: RetryPolicy,
  shouldRetry: (err: unknown) => boolean,
  op: () => Promise<T>,
): Promise<T> {
  if (policy.maxAttempts < 1) {
    throw new Error("RetryPolicy.maxAttempts must be >= 1");
  }

  let lastErr: unknown;
  for (let attempt = 1; attempt <= policy.maxAttempts; attempt++) {
    try {
      return await op();
    } catch (err) {
      lastErr = err;
      const isLast = attempt === policy.maxAttempts;
      if (isLast || !shouldRetry(err)) {
        throw err;
      }
      await sleep(RetryPolicy.backoffForAttemptMs(policy, attempt + 1));
    }
  }
  // Unreachable; the loop either returns or throws above.
  throw lastErr;
}
