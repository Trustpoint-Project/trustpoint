from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.request import urlopen

from django.conf import settings
from django.core import mail
from django.test import SimpleTestCase, override_settings

from workflows2.engine.adapters import DjangoEmailAdapter, RequestsWebhookAdapter


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


# -----------------------------
# HTTP test server (real socket)
# -----------------------------

class _AdapterTestHandler(BaseHTTPRequestHandler):
    received: list[dict] = []
    response_status: int = 200
    response_json: dict | None = {"ok": True}
    response_text: str = "OK"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""

        try:
            req_body = json.loads(raw.decode("utf-8")) if raw else None
        except Exception:
            req_body = raw.decode("utf-8", errors="replace")

        self.__class__.received.append(
            {
                "method": "POST",
                "path": self.path,
                "headers": {str(k): str(v) for k, v in self.headers.items()},
                "body": req_body,
            }
        )

        self.send_response(self.__class__.response_status)

        if self.__class__.response_json is not None:
            payload = json.dumps(self.__class__.response_json).encode("utf-8")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Adapter-Test", "1")
            self.end_headers()
            self.wfile.write(payload)
        else:
            payload = self.__class__.response_text.encode("utf-8")
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("X-Adapter-Test", "1")
            self.end_headers()
            self.wfile.write(payload)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _start_http_server() -> tuple[HTTPServer, str]:
    httpd = HTTPServer(("127.0.0.1", 0), _AdapterTestHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    host, port = httpd.server_address
    return httpd, f"http://{host}:{port}"


# -----------------------------
# RequestsWebhookAdapter tests
# -----------------------------

class RequestsWebhookAdapterTests(SimpleTestCase):
    def setUp(self) -> None:
        _AdapterTestHandler.received.clear()
        _AdapterTestHandler.response_status = 200
        _AdapterTestHandler.response_json = {"ok": True}
        _AdapterTestHandler.response_text = "OK"

    def test_request_returns_200_and_parses_json(self) -> None:
        httpd, base = _start_http_server()
        try:
            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url=f"{base}/hook",
                headers={"X-Test": "1"},
                body={"hello": "world"},
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.body, {"ok": True})
            self.assertIn("X-Adapter-Test", resp.headers)

            self.assertEqual(len(_AdapterTestHandler.received), 1)
            r = _AdapterTestHandler.received[0]
            self.assertEqual(r["method"], "POST")
            self.assertEqual(r["path"], "/hook")
            self.assertEqual(r["body"], {"hello": "world"})
            self.assertEqual(r["headers"].get("X-Test"), "1")
        finally:
            httpd.shutdown()

    def test_request_returns_non_200_and_preserves_status_code(self) -> None:
        httpd, base = _start_http_server()
        try:
            _AdapterTestHandler.response_status = 418
            _AdapterTestHandler.response_json = {"teapot": True}

            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url=f"{base}/teapot",
                headers={},
                body={"x": 1},
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 418)
            self.assertEqual(resp.body, {"teapot": True})
            self.assertEqual(len(_AdapterTestHandler.received), 1)
            self.assertEqual(_AdapterTestHandler.received[0]["path"], "/teapot")
        finally:
            httpd.shutdown()

    def test_request_falls_back_to_text_when_response_is_not_json(self) -> None:
        httpd, base = _start_http_server()
        try:
            _AdapterTestHandler.response_status = 200
            _AdapterTestHandler.response_json = None
            _AdapterTestHandler.response_text = "NOT JSON"

            adapter = RequestsWebhookAdapter(verify_tls=True)

            resp = adapter.request(
                method="POST",
                url=f"{base}/plain",
                headers={},
                body="raw-body",
                timeout_seconds=5,
            )

            self.assertEqual(resp.status_code, 200)
            self.assertEqual(resp.body, "NOT JSON")
        finally:
            httpd.shutdown()


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
