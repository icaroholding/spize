"""Spize SDK exception hierarchy."""


class SpizeError(Exception):
    """Root class for SDK errors."""


class SpizeHTTPError(SpizeError):
    """Raised when the control plane returns a non-2xx response.

    ``runbook_url`` (Sprint 3, AEX Delight #3) is an optional link to
    an operator-facing markdown page describing how to recover from
    this specific failure mode. Absent for server versions older than
    v1.3.0-beta.1 or for errors the server hasn't mapped yet — callers
    should treat missing runbooks as "use :attr:`message` as-is".
    """

    def __init__(
        self,
        status_code: int,
        code: str | None,
        message: str,
        runbook_url: str | None = None,
    ) -> None:
        runbook_suffix = f" [runbook: {runbook_url}]" if runbook_url else ""
        super().__init__(
            f"[{status_code}] {code or 'error'}: {message}{runbook_suffix}"
        )
        self.status_code = status_code
        self.code = code
        self.message = message
        self.runbook_url = runbook_url


class IdentityError(SpizeError):
    """Raised for identity-file corruption or mismatched keys."""
