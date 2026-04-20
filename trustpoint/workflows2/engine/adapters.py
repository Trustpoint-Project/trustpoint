"""Runtime adapters for sending emails and webhooks."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import requests
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
            error_msg = 'email.to must not be empty'
            raise ValueError(error_msg)

        email_message = EmailMultiAlternatives(
            subject=subject,
            body=body,
            from_email=self.default_from_email,
            to=to,
            cc=cc,
            bcc=bcc,
        )
        email_message.send(fail_silently=False)


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
        if not self.verify_tls:
            return False

        if self.ca_bundle:
            return self.ca_bundle

        env_bundle = os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('SSL_CERT_FILE')
        if env_bundle:
            return env_bundle

        candidates = (
            Path('/etc/ssl/cert.pem'),
            Path('/etc/ssl/certs/ca-certificates.crt'),
            Path('/etc/ssl/certs'),
        )
        for candidate in candidates:
            if candidate.exists():
                return str(candidate)

        return True

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
        normalized_method = method.upper().strip()
        if normalized_method not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
            error_msg = f'Unsupported method: {method}'
            raise ValueError(error_msg)

        verify = self._resolve_verify()
        request_kwargs: dict[str, Any] = {
            'headers': headers or {},
            'verify': verify,
        }

        if body is None:
            pass
        elif isinstance(body, (dict, list)):
            request_kwargs['json'] = body
        else:
            request_kwargs['data'] = body

        try:
            resp = requests.request(
                normalized_method,
                url,
                timeout=timeout_seconds,
                **request_kwargs,
            )
        except requests.exceptions.SSLError as exc:
            error_msg = (
                'TLS verification failed while calling webhook.\n'
                'Fix options:\n'
                '- Install newer CA certificates in the runtime (container/VM).\n'
                '- If you are behind a corporate proxy, add the corporate root CA to the OS trust store.\n'
                '- Or configure REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem '
                '(or SSL_CERT_FILE=...).\n'
                f'Effective verify setting was: {verify!r}\n'
                f'Original error: {exc!r}'
            )
            raise RuntimeError(error_msg) from exc

        resp_headers = {str(k): str(v) for k, v in resp.headers.items()}

        try:
            parsed_body: Any = resp.json()
        except ValueError:
            parsed_body = resp.text

        return WebhookResponse(
            status_code=int(resp.status_code),
            body=parsed_body,
            headers=resp_headers,
        )
