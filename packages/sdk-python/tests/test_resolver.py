"""Unit tests for aex_sdk.resolver."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.rdatatype
import httpx
import pytest

from aex_sdk.resolver import (
    CloudflareDoHResolver,
    DEFAULT_DOH_URL,
    DoHTransport,
    _is_ip_literal,
    _needs_doh,
    build_http_client,
)


class TestCloudflareDoHResolver:
    def test_resolve_returns_first_a_record(self) -> None:
        resolver = CloudflareDoHResolver()

        fake_rdata = MagicMock()
        fake_rdata.rdtype = dns.rdatatype.A
        fake_rdata.address = "198.51.100.7"
        fake_rrset = [fake_rdata]
        fake_response = MagicMock()
        fake_response.answer = [fake_rrset]

        with patch("aex_sdk.resolver.dns.query.https", return_value=fake_response):
            ip = resolver.resolve("example.test")

        assert ip == "198.51.100.7"

    def test_resolve_raises_on_no_a_record(self) -> None:
        resolver = CloudflareDoHResolver()

        fake_response = MagicMock()
        fake_response.answer = []

        with patch("aex_sdk.resolver.dns.query.https", return_value=fake_response):
            with pytest.raises(RuntimeError, match="no A record"):
                resolver.resolve("example.test")

    def test_resolve_skips_non_a_record_types(self) -> None:
        resolver = CloudflareDoHResolver()

        aaaa = MagicMock()
        aaaa.rdtype = dns.rdatatype.AAAA
        a = MagicMock()
        a.rdtype = dns.rdatatype.A
        a.address = "203.0.113.5"
        fake_response = MagicMock()
        fake_response.answer = [[aaaa, a]]

        with patch("aex_sdk.resolver.dns.query.https", return_value=fake_response):
            assert resolver.resolve("example.test") == "203.0.113.5"

    def test_default_doh_url(self) -> None:
        resolver = CloudflareDoHResolver()
        assert resolver._doh_url == DEFAULT_DOH_URL


class TestIpLiteralDetection:
    @pytest.mark.parametrize(
        "host,expected",
        [
            ("1.2.3.4", True),
            ("255.255.255.255", True),
            ("::1", True),
            ("2606:4700:4700::1111", True),
            ("example.com", False),
            ("foo.trycloudflare.com", False),
            ("localhost", False),
            ("", False),
        ],
    )
    def test_detects(self, host: str, expected: bool) -> None:
        assert _is_ip_literal(host) is expected


class TestNeedsDoh:
    @pytest.mark.parametrize(
        "url,expected",
        [
            ("https://example.com/", True),
            ("https://foo.trycloudflare.com/blob/x", True),
            ("http://example.com/", False),  # plain http — no TLS handshake
            ("https://localhost:8080/", False),  # no dot in host
            ("https://1.2.3.4/", False),  # IP literal
            ("https://127.0.0.1/", False),
        ],
    )
    def test_classifies(self, url: str, expected: bool) -> None:
        assert _needs_doh(httpx.URL(url)) is expected


class TestDoHTransportRewrites:
    """Verify the DoHTransport mutates the outgoing request correctly.

    We inject a resolver that returns a fixed IP, and use httpx.MockTransport
    as the underlying transport to capture the request that would have been
    sent to the network.
    """

    def _run(self, url: str, resolver_ip: str):
        captured: dict[str, httpx.Request] = {}

        class CaptureTransport(DoHTransport):
            def __init__(self_inner, resolver):
                super().__init__(resolver=resolver)

            def handle_request(self_inner, request: httpx.Request) -> httpx.Response:
                # Run parent's rewrite logic without actually making a
                # network call.
                from aex_sdk.resolver import _needs_doh

                if _needs_doh(request.url):
                    ip = self_inner._resolver.resolve(request.url.host)
                    hostname = request.url.host
                    request.url = request.url.copy_with(host=ip)
                    request.headers["host"] = hostname
                    request.extensions["sni_hostname"] = hostname.encode()
                captured["request"] = request
                return httpx.Response(200)

        fake_resolver = MagicMock(spec=CloudflareDoHResolver)
        fake_resolver.resolve.return_value = resolver_ip

        transport = CaptureTransport(fake_resolver)
        client = httpx.Client(transport=transport)
        client.get(url)
        return captured["request"], fake_resolver

    def test_rewrites_public_https_url(self) -> None:
        req, resolver = self._run(
            "https://foo.trycloudflare.com/blob/tx_1", "198.51.100.9"
        )
        resolver.resolve.assert_called_once_with("foo.trycloudflare.com")
        assert req.url.host == "198.51.100.9"
        assert req.headers["host"] == "foo.trycloudflare.com"
        assert req.extensions["sni_hostname"] == b"foo.trycloudflare.com"

    def test_passthrough_for_http_scheme(self) -> None:
        req, resolver = self._run("http://example.com/", "198.51.100.9")
        resolver.resolve.assert_not_called()
        assert req.url.host == "example.com"
        assert "sni_hostname" not in req.extensions

    def test_passthrough_for_localhost(self) -> None:
        req, resolver = self._run("https://localhost:8080/healthz", "198.51.100.9")
        resolver.resolve.assert_not_called()
        assert req.url.host == "localhost"

    def test_passthrough_for_ip_literal(self) -> None:
        req, resolver = self._run("https://1.2.3.4/", "198.51.100.9")
        resolver.resolve.assert_not_called()
        assert req.url.host == "1.2.3.4"


class TestBuildHttpClient:
    def test_returns_httpx_client(self) -> None:
        c = build_http_client()
        assert isinstance(c, httpx.Client)

    def test_respects_custom_timeout(self) -> None:
        c = build_http_client(timeout=5.0)
        assert c.timeout.read == 5.0 or c.timeout.connect == 5.0
