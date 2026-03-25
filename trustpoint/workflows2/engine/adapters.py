"""Runtime adapters for sending emails and webhooks."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from django.conf import settings
from django.core.mail import EmailMultiAlternatives


@dataclass(frozen=True)
class WebhookResponse:
    """Normalized webhook response returned by adapter implementations."""

    status_code: int
    body: Any
    headers: dict[str, str]


class EmailAdapter(Protocol):
    """Protocol for email-sending backends."""

    def send(
        self,
        *,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        subject: str,
        body: str,
    ) -> None:
        """Send one email message."""
        ...


class WebhookAdapter(Protocol):
    """Protocol for webhook HTTP backends."""

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
        timeout_seconds: int,
    ) -> WebhookResponse:
        """Execute one webhook request and return a normalized response."""
        ...


class DjangoEmailAdapter:
    """Send email through Django's configured email backend."""

    def __init__(self, *, default_from_email: str | None = None) -> None:
        """Initialize the adapter with an optional default sender address."""
        self.default_from_email = default_from_email or getattr(settings, 'DEFAULT_FROM_EMAIL', None)

    def send(
        self,
        *,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        subject: str,
        body: str,
    ) -> None:
        """Send one email message."""
        if not to:
            raise ValueError('email.to must not be empty')

        msg = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=self.default_from_email,
            to=to,
            cc=cc,
            bcc=bcc,
        )
        msg.send(fail_silently=False)


class RequestsWebhookAdapter:
    """HTTP client adapter using requests.

    TLS verification behavior:
    - If verify_tls=False: disables TLS verification (not recommended except local dev).
    - Else if ca_bundle provided: uses that path for verification (PEM file or directory).
    - Else if env var REQUESTS_CA_BUNDLE or SSL_CERT_FILE is set: uses that.
    - Else: requests default (certifi).

    Body handling:
    - dict/list => JSON
    - otherwise => raw data

    Response handling:
    - parse JSON if possible; else text
    """

    def __init__(
        self,
        *,
        verify_tls: bool = True,
        ca_bundle: str | None = None,
    ) -> None:
        """Initialize webhook TLS verification settings."""
        self.verify_tls = verify_tls
        self.ca_bundle = ca_bundle

    def _resolve_verify(self) -> bool | str:
        import os

        if not self.verify_tls:
            return False

        # 1) Explicitly passed in
        if self.ca_bundle:
            return self.ca_bundle

        # 2) Environment override (very common in containers / corporate environments)
        env_bundle = os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
        if env_bundle:
            return env_bundle

        # 3) If system CA bundle exists, prefer it (helps when corp CA is installed to OS store)
        #    If neither exists, fall back to requests default (certifi).
        candidates = ('/etc/ssl/cert.pem', '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/certs')
        for p in candidates:
            if os.path.exists(p):
                return p

        return True  # requests default (certifi)

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
        timeout_seconds: int,
    ) -> WebhookResponse:
        """Execute one webhook HTTP request and normalize the response."""
        import requests  # type: ignore[import-untyped]  # keep local import so tests can stub easily

        m = method.upper().strip()
        if m not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
            raise ValueError(f'Unsupported method: {method}')

        kwargs: dict[str, Any] = {
            'headers': headers or {},
            'timeout': timeout_seconds,
            'verify': self._resolve_verify(),
        }

        if body is None:
            pass
        elif isinstance(body, (dict, list)):
            kwargs['json'] = body
        else:
            kwargs['data'] = body

        try:
            resp = requests.request(m, url, **kwargs)
        except requests.exceptions.SSLError as e:
            # Give a targeted hint without disabling TLS.
            raise RuntimeError(
                "TLS verification failed while calling webhook.\n"
                "Fix options:\n"
                "- Install/update CA certificates in the runtime (container/VM).\n"
                "- If you're behind a corporate proxy, add the corporate root CA to the OS trust store.\n"
                "- Or set REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem (or SSL_CERT_FILE=...).\n"
                f"Effective verify setting was: {kwargs.get('verify')!r}\n"
                f"Original error: {e!r}"
            ) from e

        resp_headers = {str(k): str(v) for k, v in resp.headers.items()}

        try:
            parsed_body: Any = resp.json()
        except Exception:
            parsed_body = resp.text

        return WebhookResponse(
            status_code=int(resp.status_code),
            body=parsed_body,
            headers=resp_headers,
        )
