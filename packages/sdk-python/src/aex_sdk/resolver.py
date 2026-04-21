"""DNS-over-HTTPS resolver + httpx transport that bypasses the OS resolver.

Mirrors the Rust `aex-net` crate's ``dns`` + ``http`` modules. See
`docs/protocol-v1.md` §5.3 and the crate docs for the rationale — the short
version is that consumer wifi networks routinely inject a search-domain
suffix into `resolv.conf`, and macOS caches NXDOMAIN for ~60s, either of
which will corrupt lookups of a freshly-minted Cloudflare quick-tunnel
hostname. Using DoH against ``cloudflare-dns.com`` routes around both.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

import dns.message
import dns.query
import dns.rdatatype
import httpx


DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query"
DEFAULT_DOH_TIMEOUT = 10.0


class CloudflareDoHResolver:
    """Resolve A records for a hostname via Cloudflare DNS-over-HTTPS.

    The resolver holds no state besides configuration; it is safe to share
    across threads. Each call to :meth:`resolve` performs a fresh DoH query,
    matching the Rust crate's zero-cache behaviour.
    """

    def __init__(
        self,
        doh_url: str = DEFAULT_DOH_URL,
        timeout: float = DEFAULT_DOH_TIMEOUT,
    ) -> None:
        self._doh_url = doh_url
        self._timeout = timeout

    def resolve(self, hostname: str) -> str:
        """Return the first A record for ``hostname`` as a dotted-quad string.

        Raises :class:`RuntimeError` if the DoH query fails or returns no
        A record. Intentionally does not silently fall back to the OS
        resolver — the whole point of this class is to avoid it.
        """
        query = dns.message.make_query(hostname, dns.rdatatype.A)
        # Force HTTP/2 for the DoH transport. dnspython's default tries
        # HTTP/3 first, which raises `NoDOH` when the optional `aioquic`
        # dependency isn't installed. AEX does not require HTTP/3 for
        # DoH — any stack with TLS will do — so we pin H2 to keep the
        # dependency surface small.
        response = dns.query.https(
            query,
            self._doh_url,
            timeout=self._timeout,
            http_version=dns.query.HTTPVersion.H2,
        )
        for rrset in response.answer:
            for rdata in rrset:
                if rdata.rdtype == dns.rdatatype.A:
                    return rdata.address  # type: ignore[no-any-return]
        raise RuntimeError(f"no A record returned for {hostname!r}")


class DoHTransport(httpx.HTTPTransport):
    """httpx transport that pre-resolves hostnames via DoH before connecting.

    Behaviour:

    - For ``https://`` URLs whose host is a DNS name (contains at least one
      dot and is not already an IP literal), the transport asks the resolver
      for the hostname's A record, rewrites the outgoing request's URL to
      point at that IP, sets the ``Host`` header back to the original
      hostname, and sets the httpcore ``sni_hostname`` extension so the TLS
      handshake uses the right SNI and the certificate is verified against
      the hostname.
    - For ``http://``, localhost, short unqualified names, or IP literals,
      the request is passed through unchanged — no DoH lookup, no rewrite.

    This mirrors the ``curl --resolve HOST:443:IP`` pattern the Sprint 1
    demo used via subprocess.
    """

    def __init__(
        self,
        resolver: Optional[CloudflareDoHResolver] = None,
        **transport_kwargs,
    ) -> None:
        super().__init__(**transport_kwargs)
        self._resolver = resolver or CloudflareDoHResolver()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if _needs_doh(request.url):
            hostname = request.url.host
            ip = self._resolver.resolve(hostname)
            request.url = request.url.copy_with(host=ip)
            request.headers["host"] = hostname
            request.extensions["sni_hostname"] = hostname.encode()
        return super().handle_request(request)


def _needs_doh(url: httpx.URL) -> bool:
    """True if ``url`` is an HTTPS URL whose host is a public DNS name.

    Pass-through for HTTP (plain), IP literals, and single-label hostnames
    like ``localhost``.
    """
    if url.scheme != "https":
        return False
    host = url.host
    if not host or "." not in host:
        return False
    return not _is_ip_literal(host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def build_http_client(
    *,
    resolver: Optional[CloudflareDoHResolver] = None,
    timeout: float = 30.0,
) -> httpx.Client:
    """Return an ``httpx.Client`` that pre-resolves public hostnames via DoH.

    Mirrors the Rust ``aex_net::build_http_client`` factory. Use this for any
    SDK operation that talks to an AEX data plane over a public URL.
    """
    transport = DoHTransport(resolver=resolver or CloudflareDoHResolver())
    return httpx.Client(transport=transport, timeout=timeout)
