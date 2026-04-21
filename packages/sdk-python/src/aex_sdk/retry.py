"""Exponential-backoff retry helpers. Mirrors the Rust ``aex-net::retry`` module.

See ``docs/protocol-v1.md`` §5.1 for the normative spec. The values in
:meth:`RetryPolicy.normative` are pinned to that spec and must match the
matching Rust and TypeScript implementations byte-for-byte.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar


T = TypeVar("T")
E = TypeVar("E", bound=BaseException)


@dataclass(frozen=True)
class RetryPolicy:
    """Exponential-backoff retry policy with bounded jitter.

    Sleep before attempt ``n`` (1-indexed):

    - ``n == 1``: 0 (first attempt runs immediately).
    - ``n >= 2``: ``base_delay * multiplier^(n-2) + U(-jitter, +jitter)``,
      clamped to non-negative.
    """

    max_attempts: int
    base_delay: float
    """Base delay in seconds."""
    multiplier: float
    jitter: float
    """Jitter half-width in seconds."""

    @classmethod
    def normative(cls) -> "RetryPolicy":
        """Return the AEX normative retry policy per protocol-v1 §5.1.

        3 attempts, 1 s base, 2× multiplier, ±100 ms jitter.
        """
        return cls(max_attempts=3, base_delay=1.0, multiplier=2.0, jitter=0.1)

    def backoff_for_attempt(self, attempt: int) -> float:
        """Seconds to sleep *before* attempt ``n`` (1-indexed)."""
        if attempt <= 1:
            return 0.0
        exp = attempt - 2
        base = self.base_delay * (self.multiplier**exp)
        if self.jitter > 0:
            j = random.uniform(-self.jitter, self.jitter)
        else:
            j = 0.0
        return max(0.0, base + j)


def retry_with_backoff(
    policy: RetryPolicy,
    should_retry: Callable[[BaseException], bool],
    op: Callable[[], T],
) -> T:
    """Run ``op`` with bounded retry on exception.

    - ``policy`` controls max attempts and backoff curve.
    - ``should_retry`` inspects each raised exception and returns whether
      the failure is transient and worth retrying.
    - ``op`` is the zero-argument callable under retry. It is re-invoked
      once per retry.

    Returns the first successful result. Re-raises the last exception on
    exhaustion or on a non-retriable failure.
    """
    if policy.max_attempts < 1:
        raise ValueError("RetryPolicy.max_attempts must be >= 1")

    last_exc: BaseException | None = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return op()
        except BaseException as exc:
            last_exc = exc
            is_last = attempt == policy.max_attempts
            if is_last or not should_retry(exc):
                raise
            time.sleep(policy.backoff_for_attempt(attempt + 1))

    # Unreachable under normal control flow — the loop always returns or
    # re-raises. Kept as a safety net for the type-checker.
    assert last_exc is not None
    raise last_exc
