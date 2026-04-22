"""Sprint 3 Delight #3: SpizeHTTPError exposes the server's runbook_url.

Server responses that contain a ``runbook_url`` in the JSON error body
must surface on the exception as ``SpizeHTTPError.runbook_url`` so
operators can jump straight to remediation docs. Responses without
the field (older CPs) must set it to ``None`` — no crashes, no
fabrication.
"""

from __future__ import annotations

import httpx
import pytest

from aex_sdk import Identity, SpizeClient
from aex_sdk.errors import SpizeHTTPError


def _client_with_mock(identity: Identity, handler) -> SpizeClient:
    transport = httpx.MockTransport(handler)
    client = SpizeClient("http://test", identity)
    client._http.close()
    client._http = httpx.Client(base_url="http://test", transport=transport)
    return client


def test_runbook_url_surfaces_on_exception() -> None:
    alice = Identity.generate(org="acme", name="alice")
    runbook = (
        "https://github.com/icaroholding/aex/blob/master/docs/runbooks/"
        "signature-invalid.md"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={
                "code": "unauthorized",
                "message": "signature does not match challenge",
                "runbook_url": runbook,
            },
        )

    client = _client_with_mock(alice, handler)
    try:
        with pytest.raises(SpizeHTTPError) as excinfo:
            client.register()
        err = excinfo.value
        assert err.status_code == 401
        assert err.code == "unauthorized"
        assert err.runbook_url == runbook
        assert runbook in str(err), "runbook URL should appear in str(err)"
    finally:
        client.close()


def test_missing_runbook_url_is_none() -> None:
    # Older control planes (pre-v1.3.0-beta.1) don't emit the field —
    # the SDK must tolerate its absence.
    alice = Identity.generate(org="acme", name="alice")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "code": "conflict",
                "message": "some older-server conflict without a runbook",
            },
        )

    client = _client_with_mock(alice, handler)
    try:
        with pytest.raises(SpizeHTTPError) as excinfo:
            client.register()
        assert excinfo.value.runbook_url is None
    finally:
        client.close()


def test_runbook_url_accepts_keyword_argument_directly() -> None:
    # Sanity: the constructor signature is stable for code that
    # builds SpizeHTTPError manually (e.g. custom retry middleware).
    err = SpizeHTTPError(
        status_code=500,
        code="internal_error",
        message="internal server error",
        runbook_url="https://example/runbooks/internal-error.md",
    )
    assert err.runbook_url == "https://example/runbooks/internal-error.md"
