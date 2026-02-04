# workflows2/engine/context.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RuntimeContext:
    event: dict[str, Any]
    vars: dict[str, Any]
