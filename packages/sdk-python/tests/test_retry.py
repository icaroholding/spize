"""Unit tests for aex_sdk.retry."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from aex_sdk.retry import RetryPolicy, retry_with_backoff


class TestRetryPolicy:
    def test_normative_matches_protocol_v1_section_5_1(self) -> None:
        p = RetryPolicy.normative()
        assert p.max_attempts == 3
        assert p.base_delay == 1.0
        assert p.multiplier == 2.0
        assert p.jitter == pytest.approx(0.1)

    def test_first_attempt_has_zero_backoff(self) -> None:
        p = RetryPolicy.normative()
        assert p.backoff_for_attempt(1) == 0.0
        assert p.backoff_for_attempt(0) == 0.0

    def test_second_attempt_jitter_bounded(self) -> None:
        p = RetryPolicy.normative()
        for _ in range(500):
            d = p.backoff_for_attempt(2)
            assert 0.9 <= d <= 1.1, f"attempt 2 backoff {d} out of [0.9, 1.1]"

    def test_third_attempt_doubles_base(self) -> None:
        p = RetryPolicy.normative()
        for _ in range(500):
            d = p.backoff_for_attempt(3)
            assert 1.9 <= d <= 2.1, f"attempt 3 backoff {d} out of [1.9, 2.1]"


class TestRetryWithBackoff:
    # time.sleep is patched throughout so tests don't actually wait.

    def test_success_first_attempt(self) -> None:
        calls = {"n": 0}

        def op() -> int:
            calls["n"] += 1
            return 42

        with patch("aex_sdk.retry.time.sleep") as sleep_mock:
            result = retry_with_backoff(RetryPolicy.normative(), lambda _e: True, op)

        assert result == 42
        assert calls["n"] == 1
        sleep_mock.assert_not_called()

    def test_success_after_two_transient_failures(self) -> None:
        calls = {"n": 0}

        def op() -> int:
            calls["n"] += 1
            if calls["n"] < 3:
                raise RuntimeError("transient")
            return 7

        with patch("aex_sdk.retry.time.sleep"):
            result = retry_with_backoff(RetryPolicy.normative(), lambda _e: True, op)

        assert result == 7
        assert calls["n"] == 3

    def test_raises_last_error_on_exhaustion(self) -> None:
        calls = {"n": 0}

        def op() -> int:
            calls["n"] += 1
            raise RuntimeError(f"fail {calls['n']}")

        with patch("aex_sdk.retry.time.sleep"):
            with pytest.raises(RuntimeError, match="fail 3"):
                retry_with_backoff(RetryPolicy.normative(), lambda _e: True, op)

        assert calls["n"] == 3

    def test_non_retriable_error_short_circuits(self) -> None:
        calls = {"n": 0}

        class PermanentError(RuntimeError):
            pass

        def op() -> int:
            calls["n"] += 1
            raise PermanentError("nope")

        with patch("aex_sdk.retry.time.sleep"):
            with pytest.raises(PermanentError):
                retry_with_backoff(
                    RetryPolicy.normative(),
                    lambda e: not isinstance(e, PermanentError),
                    op,
                )

        assert calls["n"] == 1

    def test_rejects_invalid_max_attempts(self) -> None:
        with pytest.raises(ValueError):
            retry_with_backoff(
                RetryPolicy(
                    max_attempts=0, base_delay=1.0, multiplier=2.0, jitter=0.1
                ),
                lambda _e: True,
                lambda: 42,
            )
