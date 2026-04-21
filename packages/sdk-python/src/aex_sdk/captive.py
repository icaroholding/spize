"""Captive-portal detection via three standard probe endpoints.

Python mirror of the Rust ``aex-net::captive`` module; behaviour matches
``detect_network_state`` in Rust to the precision described by
``docs/protocol-v1.md`` §5.3.

Consensus rules (first match wins):

- Any probe saw a redirect or login-page body → ``NetworkState.CAPTIVE_PORTAL``
- All three probes behaved as expected → ``NetworkState.DIRECT``
- All three probes failed to complete → ``NetworkState.UNKNOWN``
- Any other mix → ``NetworkState.LIMITED``
"""

from __future__ import annotations

import enum
from typing import Iterable, Optional

import httpx


APPLE_URL = "http://captive.apple.com/hotspot-detect.html"
GOOGLE_URL = "http://www.google.com/generate_204"
MS_URL = "http://www.msftncsi.com/ncsi.txt"

APPLE_EXPECTED_BODY_FRAGMENT = "Success"
MS_EXPECTED_BODY = "Microsoft NCSI"

PROBE_TIMEOUT = 5.0


class NetworkState(str, enum.Enum):
    """High-level network reachability state.

    Serialised as lowercase snake_case so the value stream-to the
    ``AEX_NETWORK_STATE=<value>`` stdout flag matches the Rust crate's
    ``NetworkState::as_stdout_value``.
    """

    DIRECT = "direct"
    CAPTIVE_PORTAL = "captive_portal"
    LIMITED = "limited"
    UNKNOWN = "unknown"


class _ProbeVerdict(str, enum.Enum):
    OK = "ok"
    CAPTIVE = "captive"
    UNEXPECTED = "unexpected"
    FAILED = "failed"


def detect_network_state(
    client: Optional[httpx.Client] = None,
    *,
    apple_url: str = APPLE_URL,
    google_url: str = GOOGLE_URL,
    ms_url: str = MS_URL,
) -> NetworkState:
    """Fire the three probes and return the consensus state.

    ``client`` is optional; if omitted a short-lived :class:`httpx.Client`
    is constructed with follow_redirects=False. Callers who want the
    probe traffic to go through DoH should pass a client built by
    :func:`aex_sdk.resolver.build_http_client`.
    """
    owns_client = client is None
    if client is None:
        client = httpx.Client(follow_redirects=False, timeout=PROBE_TIMEOUT)
    try:
        results = [
            _probe_apple(client, apple_url),
            _probe_google(client, google_url),
            _probe_ms(client, ms_url),
        ]
    finally:
        if owns_client:
            client.close()

    return _consensus(results)


def _consensus(results: Iterable[_ProbeVerdict]) -> NetworkState:
    results = list(results)
    if _ProbeVerdict.CAPTIVE in results:
        return NetworkState.CAPTIVE_PORTAL
    if all(v == _ProbeVerdict.OK for v in results):
        return NetworkState.DIRECT
    if all(v == _ProbeVerdict.FAILED for v in results):
        return NetworkState.UNKNOWN
    return NetworkState.LIMITED


def _probe_apple(client: httpx.Client, url: str) -> _ProbeVerdict:
    try:
        r = client.get(url, timeout=PROBE_TIMEOUT)
    except httpx.HTTPError:
        return _ProbeVerdict.FAILED
    if r.is_redirect:
        return _ProbeVerdict.CAPTIVE
    if not r.is_success:
        return _ProbeVerdict.UNEXPECTED
    return (
        _ProbeVerdict.OK
        if APPLE_EXPECTED_BODY_FRAGMENT in r.text
        else _ProbeVerdict.CAPTIVE
    )


def _probe_google(client: httpx.Client, url: str) -> _ProbeVerdict:
    try:
        r = client.get(url, timeout=PROBE_TIMEOUT)
    except httpx.HTTPError:
        return _ProbeVerdict.FAILED
    if r.is_redirect:
        return _ProbeVerdict.CAPTIVE
    if r.status_code == 204:
        return _ProbeVerdict.OK
    return _ProbeVerdict.UNEXPECTED


def _probe_ms(client: httpx.Client, url: str) -> _ProbeVerdict:
    try:
        r = client.get(url, timeout=PROBE_TIMEOUT)
    except httpx.HTTPError:
        return _ProbeVerdict.FAILED
    if r.is_redirect:
        return _ProbeVerdict.CAPTIVE
    if not r.is_success:
        return _ProbeVerdict.UNEXPECTED
    return (
        _ProbeVerdict.OK
        if r.text.strip() == MS_EXPECTED_BODY
        else _ProbeVerdict.CAPTIVE
    )
