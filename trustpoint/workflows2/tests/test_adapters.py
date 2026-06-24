from __future__ import annotations

import json
import socket
import time
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import urlopen

from django.conf import settings
from django.core import mail
from django.test import SimpleTestCase, TestCase, override_settings

from management.models import NotificationModel, NotificationStatus
from workflows2.engine.adapters import (
    DjangoEmailAdapter,
    DjangoNotificationAdapter,
    NotificationCreateRequest,
    RequestsWebhookAdapter,
)


# -----------------------------
# Helpers
# -----------------------------

def _tcp_can_connect(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _mailpit_list_subjects() -> list[str]:
    # Mailpit API is on 8025 (HTTP)
    with urlopen("http://mailpit:8025/api/v1/messages", timeout=5) as r:
        data = json.load(r)
    msgs = data.get("messages") or []
    subjects: list[str] = []
    for m in msgs:
        subj = m.get("Subject") or m.get("subject") or ""
        if isinstance(subj, str):
            subjects.append(subj)
    return subjects


def _build_mock_response(*, status_code: int, headers: dict[str, str], json_body=None, text_body: str = "OK"):
    class _Response:
        def __init__(self) -> None:
            self.status_code = status_code
            self.headers = headers
            self.text = text_body

        def json(self):
            if json_body is None:
                raise ValueError("No JSON body")
            return json_body

    return _Response()


# -----------------------------
# RequestsWebhookAdapter tests
# -----------------------------

class RequestsWebhookAdapterTests(SimpleTestCase):
    def test_request_returns_200_and_parses_json(self) -> None:
        with patch("requests.request") as request_mock:
            request_mock.return_value = _build_mock_response(
                status_code=200,
                headers={"X-Adapter-Test": "1"},
                json_body={"ok": True},
            )
            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url="https://example.test/hook",
                headers={"X-Test": "1"},
                body={"hello": "world"},
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.body, {"ok": True})
            self.assertIn("X-Adapter-Test", resp.headers)

            request_mock.assert_called_once()
            _, kwargs = request_mock.call_args
            self.assertEqual(kwargs["headers"].get("X-Test"), "1")
            self.assertEqual(kwargs["json"], {"hello": "world"})

    def test_request_returns_non_200_and_preserves_status_code(self) -> None:
        with patch("requests.request") as request_mock:
            request_mock.return_value = _build_mock_response(
                status_code=418,
                headers={"X-Adapter-Test": "1"},
                json_body={"teapot": True},
            )
            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url="https://example.test/teapot",
                headers={},
                body={"x": 1},
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 418)
            self.assertEqual(resp.body, {"teapot": True})
            request_mock.assert_called_once()

    def test_request_falls_back_to_text_when_response_is_not_json(self) -> None:
        with patch("requests.request") as request_mock:
            request_mock.return_value = _build_mock_response(
                status_code=200,
                headers={"X-Adapter-Test": "1"},
                json_body=None,
                text_body="NOT JSON",
            )
            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url="https://example.test/plain",
                headers={},
                body="raw-body",
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.body, "NOT JSON")
            request_mock.assert_called_once()


# -----------------------------
# DjangoEmailAdapter tests
# -----------------------------

class DjangoEmailAdapterTests(SimpleTestCase):
    def test_send_locmem_is_deterministic(self) -> None:
        # Always keep one deterministic unit-style test
        with override_settings(
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
            DEFAULT_FROM_EMAIL="no-reply@test.local",
        ):
            mail.outbox.clear()
            adapter = DjangoEmailAdapter()

            adapter.send(
                to=["test@example.com"],
                cc=[],
                bcc=[],
                subject="Adapter locmem test",
                body="Hello from locmem",
            )

            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0].subject, "Adapter locmem test")
            self.assertIn("Hello", mail.outbox[0].body)

    def test_send_really_delivers_to_mailpit_when_available(self) -> None:
        """
        IMPORTANT:
        Django tests default to locmem backend even if your settings.py says SMTP.
        So this test forces SMTP->mailpit and then PROVES the message arrived by
        querying Mailpit's HTTP API.
        """
        if not _tcp_can_connect("mailpit", 1025, timeout=2.0):
            self.skipTest("mailpit SMTP not reachable at mailpit:1025 from this container")

        # If mailpit API isn't reachable, we can't verify delivery.
        try:
            before_subjects = _mailpit_list_subjects()
        except URLError:
            self.skipTest("mailpit API not reachable at http://mailpit:8025 from this container")

        subject = f"Workflows2 adapter mailpit test {time.time()}"

        with override_settings(
            EMAIL_BACKEND="django.core.mail.backends.smtp.EmailBackend",
            EMAIL_HOST="mailpit",
            EMAIL_PORT=1025,
            EMAIL_USE_TLS=False,
            EMAIL_USE_SSL=False,
            EMAIL_TIMEOUT=10,
            DEFAULT_FROM_EMAIL=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@trustpoint.local"),
        ):
            adapter = DjangoEmailAdapter()
            adapter.send(
                to=["adapter-test@trustpoint.local"],
                cc=[],
                bcc=[],
                subject=subject,
                body="https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            )

        # Poll Mailpit for the new message
        last = before_subjects
        found = False
        for _ in range(40):  # ~10s
            last = _mailpit_list_subjects()
            if subject in last:
                found = True
                break
            time.sleep(0.25)

        self.assertTrue(
            found,
            "Mailpit did NOT receive the message.\n"
            f"Subjects before (first 20): {before_subjects[:20]}\n"
            f"Subjects after  (first 20): {last[:20]}",
        )


class DjangoNotificationAdapterTests(TestCase):
    def test_create_stores_custom_notification_message_and_initial_status(self) -> None:
        adapter = DjangoNotificationAdapter()

        result = adapter.create(
            NotificationCreateRequest(
                severity="warning",
                source="system",
                short="Workflow needs review",
                long="",
                initial_status="new",
                event="workflow.review",
                related={},
            )
        )

        notification = NotificationModel.objects.get(id=result["notification_id"])

        self.assertEqual(notification.notification_type, NotificationModel.NotificationTypes.WARNING)
        self.assertEqual(notification.notification_source, NotificationModel.NotificationSource.SYSTEM)
        self.assertEqual(notification.message_type, NotificationModel.NotificationMessageType.CUSTOM)
        self.assertEqual(notification.event, "workflow.review")
        self.assertEqual(notification.message.short_description, "Workflow needs review")
        self.assertEqual(notification.message.long_description, "No description provided")
        self.assertTrue(notification.statuses.filter(status=NotificationStatus.StatusChoices.NEW).exists())
        self.assertEqual(result["status"], NotificationStatus.StatusChoices.NEW)

    def test_create_rejects_unknown_notification_enums(self) -> None:
        adapter = DjangoNotificationAdapter()
        base = {
            "severity": "info",
            "source": "system",
            "short": "Workflow notice",
            "long": "Details",
            "initial_status": "new",
            "event": "workflow.notice",
            "related": {},
        }

        cases = (
            ("severity", "loud", "Unsupported notification severity: loud"),
            ("source", "planet", "Unsupported notification source: planet"),
            ("initial_status", "maybe", "Unsupported notification status: maybe"),
        )
        for field, value, message in cases:
            with self.subTest(field=field):
                payload = {**base, field: value}
                with self.assertRaisesMessage(ValueError, message):
                    adapter.create(NotificationCreateRequest(**payload))

    def test_related_id_validation_accepts_only_optional_integer_values(self) -> None:
        parse = DjangoNotificationAdapter._optional_int

        self.assertIsNone(parse(None, field="device_id"))
        self.assertIsNone(parse("", field="device_id"))
        self.assertEqual(parse(7, field="device_id"), 7)
        self.assertEqual(parse(" 42 ", field="device_id"), 42)

        with self.assertRaisesMessage(TypeError, "notification.related.device_id must be an integer id"):
            parse(True, field="device_id")
        with self.assertRaisesMessage(TypeError, "notification.related.device_id must be an integer id"):
            parse("dev-1", field="device_id")
