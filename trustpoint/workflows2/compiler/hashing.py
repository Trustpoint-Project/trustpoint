"""Deterministic hashing helpers for Workflow 2 artifacts."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_text(text: str) -> str:
    """Return the SHA-256 hex digest for a UTF-8 string."""
    h = hashlib.sha256()
    h.update(text.encode('utf-8'))
    return h.hexdigest()


def sha256_json(obj: Any) -> str:
    """Return a deterministic SHA-256 digest for a JSON-serializable object.

    The JSON payload is normalized with stable key ordering and separators so
    irrelevant whitespace does not affect the hash.
    """
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(payload).hexdigest()
