"""Unit tests for aex_sdk.captive."""

from __future__ import annotations

import httpx
import pytest

from aex_sdk.captive import (
    APPLE_URL,
    GOOGLE_URL,
    MS_URL,
    NetworkState,
    _consensus,
    _ProbeVerdict,
    detect_network_state,
)


class TestConsensus:
    def test_all_ok_is_direct(self) -> None:
        r = _consensus([_ProbeVerdict.OK, _ProbeVerdict.OK, _ProbeVerdict.OK])
        assert r == NetworkState.DIRECT

    def test_any_captive_wins(self) -> None:
        r = _consensus([_ProbeVerdict.OK, _ProbeVerdict.CAPTIVE, _ProbeVerdict.OK])
        assert r == NetworkState.CAPTIVE_PORTAL

    def test_all_failed_is_unknown(self) -> None:
        r = _consensus(
            [_ProbeVerdict.FAILED, _ProbeVerdict.FAILED, _ProbeVerdict.FAILED]
        )
        assert r == NetworkState.UNKNOWN

    def test_mixed_ok_and_failed_is_limited(self) -> None:
        r = _consensus([_ProbeVerdict.OK, _ProbeVerdict.FAILED, _ProbeVerdict.FAILED])
        assert r == NetworkState.LIMITED

    def test_any_unexpected_is_limited(self) -> None:
        r = _consensus([_ProbeVerdict.OK, _ProbeVerdict.UNEXPECTED, _ProbeVerdict.OK])
        assert r == NetworkState.LIMITED


class TestNetworkStateValues:
    def test_stdout_values_stable(self) -> None:
        # These strings are load-bearing: the AEX_NETWORK_STATE=<value>
        # stdout flag has to emit exactly these tokens.
        assert NetworkState.DIRECT.value == "direct"
        assert NetworkState.CAPTIVE_PORTAL.value == "captive_portal"
        assert NetworkState.LIMITED.value == "limited"
        assert NetworkState.UNKNOWN.value == "unknown"


def _mock_client(handler) -> httpx.Client:
    """Build an httpx.Client that routes all requests through ``handler``.

    ``handler`` takes an httpx.Request and returns an httpx.Response.
    """
    transport = httpx.MockTransport(handler)
    return httpx.Client(transport=transport, follow_redirects=False)


class TestDetectNetworkState:
    def test_direct_when_all_probes_healthy(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "captive.apple.com":
                return httpx.Response(200, text="<HTML>Success</HTML>")
            if request.url.host == "www.google.com":
                return httpx.Response(204)
            if request.url.host == "www.msftncsi.com":
                return httpx.Response(200, text="Microsoft NCSI")
            return httpx.Response(500)

        client = _mock_client(handler)
        assert detect_network_state(client) == NetworkState.DIRECT

    def test_captive_when_apple_returns_login_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "captive.apple.com":
                return httpx.Response(200, text="Please sign in to continue")
            if request.url.host == "www.google.com":
                return httpx.Response(204)
            return httpx.Response(200, text="Microsoft NCSI")

        client = _mock_client(handler)
        assert detect_network_state(client) == NetworkState.CAPTIVE_PORTAL

    def test_captive_when_apple_redirects(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "captive.apple.com":
                return httpx.Response(302, headers={"location": "http://login.example"})
            if request.url.host == "www.google.com":
                return httpx.Response(204)
            return httpx.Response(200, text="Microsoft NCSI")

        client = _mock_client(handler)
        assert detect_network_state(client) == NetworkState.CAPTIVE_PORTAL

    def test_limited_when_google_returns_200_instead_of_204(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "captive.apple.com":
                return httpx.Response(200, text="Success")
            if request.url.host == "www.google.com":
                return httpx.Response(200, text="intercepted")
            return httpx.Response(200, text="Microsoft NCSI")

        client = _mock_client(handler)
        assert detect_network_state(client) == NetworkState.LIMITED

    def test_unknown_when_all_probes_fail(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("network down")

        client = _mock_client(handler)
        assert detect_network_state(client) == NetworkState.UNKNOWN

    def test_urls_match_constants(self) -> None:
        assert APPLE_URL == "http://captive.apple.com/hotspot-detect.html"
        assert GOOGLE_URL == "http://www.google.com/generate_204"
        assert MS_URL == "http://www.msftncsi.com/ncsi.txt"
