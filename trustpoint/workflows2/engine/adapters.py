"""Runtime adapters for workflow side effects."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar, Protocol

import requests
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from management.models import NotificationMessageModel, NotificationModel, NotificationStatus


@dataclass(frozen=True)
class WebhookResponse:
    """Normalized webhook response returned by adapter implementations."""

    status_code: int
    body: Any
    headers: dict[str, str]


@dataclass(frozen=True)
class NotificationCreateRequest:
    """Inputs required to create one Trustpoint notification."""

    severity: str
    source: str
    short: str
    long: str
    initial_status: str
    event: str
    related: dict[str, Any]


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


class NotificationAdapter(Protocol):
    """Protocol for Trustpoint notification backends."""

    def create(self, request: NotificationCreateRequest) -> dict[str, Any]:
        """Create one Trustpoint notification and return adapter output."""
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


class DjangoNotificationAdapter:
    """Create notifications through Trustpoint's management notification models."""

    SEVERITY_MAP: ClassVar[dict[str, str]] = {
        'setup': 'SET',
        'info': 'INF',
        'warning': 'WAR',
        'critical': 'CRI',
    }
    SOURCE_MAP: ClassVar[dict[str, str]] = {
        'system': 'S',
        'domain': 'D',
        'device': 'E',
        'issuing_ca': 'I',
        'certificate': 'C',
    }
    STATUS_MAP: ClassVar[dict[str, str]] = {
        'new': 'NEW',
        'confirmed': 'CONF',
        'in_progress': 'PROG',
        'solved': 'SOLV',
        'not_solved': 'NOSOL',
        'escalated': 'ESC',
        'suspended': 'SUS',
        'rejected': 'REJ',
        'deleted': 'DEL',
        'closed': 'CLO',
        'acknowledged': 'ACK',
        'failed': 'FAIL',
        'expired': 'EXP',
        'pending': 'PEND',
    }

    @staticmethod
    def _optional_int(value: Any, *, field: str) -> int | None:
        if value in (None, ''):
            return None
        if isinstance(value, bool):
            error_msg = f'notification.related.{field} must be an integer id'
            raise TypeError(error_msg)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        error_msg = f'notification.related.{field} must be an integer id'
        raise TypeError(error_msg)

    def create(self, request: NotificationCreateRequest) -> dict[str, Any]:
        """Create one custom Trustpoint notification."""
        notification_type = self.SEVERITY_MAP.get(request.severity)
        notification_source = self.SOURCE_MAP.get(request.source)
        status_code = self.STATUS_MAP.get(request.initial_status)
        if not notification_type:
            error_msg = f'Unsupported notification severity: {request.severity}'
            raise ValueError(error_msg)
        if not notification_source:
            error_msg = f'Unsupported notification source: {request.source}'
            raise ValueError(error_msg)
        if not status_code:
            error_msg = f'Unsupported notification status: {request.initial_status}'
            raise ValueError(error_msg)

        message = NotificationMessageModel.objects.create(
            short_description=request.short,
            long_description=request.long or 'No description provided',
        )
        notification = NotificationModel.objects.create(
            notification_type=notification_type,
            notification_source=notification_source,
            message_type=NotificationModel.NotificationMessageType.CUSTOM,
            message=message,
            event=request.event,
            device_id=self._optional_int(request.related.get('device_id'), field='device_id'),
            domain_id=self._optional_int(request.related.get('domain_id'), field='domain_id'),
            certificate_id=self._optional_int(request.related.get('certificate_id'), field='certificate_id'),
            issuing_ca_id=self._optional_int(request.related.get('issuing_ca_id'), field='issuing_ca_id'),
        )
        status, _ = NotificationStatus.objects.get_or_create(status=status_code)
        notification.statuses.add(status)

        return {
            'notification_id': str(notification.id),
            'message_id': str(message.id),
            'status': status_code,
        }


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
