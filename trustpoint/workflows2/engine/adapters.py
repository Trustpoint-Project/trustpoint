# workflows2/engine/adapters.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from django.conf import settings
from django.core.mail import EmailMultiAlternatives


@dataclass(frozen=True)
class WebhookResponse:
    status_code: int
    body: Any
    headers: dict[str, str]


class EmailAdapter(Protocol):
    def send(
        self,
        *,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        subject: str,
        body: str,
    ) -> None: ...


class WebhookAdapter(Protocol):
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
        timeout_seconds: int,
    ) -> WebhookResponse: ...


class DjangoEmailAdapter:
    """
    Uses Django's configured EMAIL_BACKEND.
    In DEBUG you already use the console backend -> safe for dev.
    """

    def __init__(self, *, default_from_email: str | None = None) -> None:
        self.default_from_email = default_from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None)

    def send(
        self,
        *,
        to: list[str],
        cc: list[str],
        bcc: list[str],
        subject: str,
        body: str,
    ) -> None:
        if not to:
            raise ValueError("email.to must not be empty")

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
    """
    HTTP client adapter using requests.
    - Sends JSON if body is dict/list, otherwise sends raw data.
    - Parses JSON response if possible, otherwise returns resp.text.
    """

    def __init__(self, *, verify_tls: bool = True) -> None:
        self.verify_tls = verify_tls

    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
        timeout_seconds: int,
    ) -> WebhookResponse:
        import requests  # keep local import so tests can stub easily

        m = method.upper().strip()
        if m not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            raise ValueError(f"Unsupported method: {method}")

        kwargs: dict[str, Any] = {
            "headers": headers or {},
            "timeout": timeout_seconds,
            "verify": self.verify_tls,
        }

        if body is None:
            pass
        elif isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["data"] = body

        resp = requests.request(m, url, **kwargs)

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
