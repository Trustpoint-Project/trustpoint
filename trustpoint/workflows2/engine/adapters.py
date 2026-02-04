# workflows2/engine/adapters.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
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


class ApprovalAdapter(Protocol):
    def await_signal(
        self,
        *,
        step_id: str,
        prompt: str | None,
        event: dict[str, Any],
        vars: dict[str, Any],
    ) -> str: ...
    # returns "approved" or "rejected" (or raise)


class NoopEmailAdapter:
    def send(self, *, to: list[str], cc: list[str], bcc: list[str], subject: str, body: str) -> None:
        return


class NoopWebhookAdapter:
    def request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str],
        body: Any,
        timeout_seconds: int,
    ) -> WebhookResponse:
        raise RuntimeError("WebhookAdapter not configured")


class NoopApprovalAdapter:
    def await_signal(self, *, step_id: str, prompt: str | None, event: dict[str, Any], vars: dict[str, Any]) -> str:
        raise RuntimeError("ApprovalAdapter not configured")
