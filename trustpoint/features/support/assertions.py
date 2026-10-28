# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Reusable response assertions for Behave tests."""

from __future__ import annotations

import json
from typing import Any


def assert_status(response: Any, expected: int) -> None:
    """Assert a response status code with useful diagnostics."""
    actual = getattr(response, 'status_code', None)
    body = getattr(response, 'content', b'')
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors='replace')
    assert actual == expected, f'Expected HTTP {expected}, got {actual}. Body: {body[:1000]}'


def response_json(response: Any) -> dict[str, Any]:
    """Return a JSON response body as a dictionary."""
    if hasattr(response, 'json'):
        data = response.json()
    else:
        raw = response.content.decode('utf-8')
        data = json.loads(raw)
    assert isinstance(data, dict), f'Expected JSON object, got {type(data).__name__}'
    return data


def assert_contains_text(response: Any, text: str) -> None:
    """Assert that rendered response content contains text."""
    content = response.content.decode('utf-8', errors='replace')
    assert text in content, f'Expected response to contain {text!r}'
