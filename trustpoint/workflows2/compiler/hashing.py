# workflows2/compiler/hashing.py
from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_text(text: str) -> str:
    h = hashlib.sha256()
    h.update(text.encode("utf-8"))
    return h.hexdigest()


def sha256_json(obj: Any) -> str:
    """
    Deterministic hash:
      - stable key ordering
      - stable separators
      - no whitespace noise
    """
    payload = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
