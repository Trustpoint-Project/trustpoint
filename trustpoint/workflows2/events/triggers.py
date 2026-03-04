# workflows2/events/triggers.py
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class Triggers:
    """Canonical trigger keys for workflows2.

    Use these everywhere instead of string literals.
    """
    DEVICE_CREATED: ClassVar[str] = "device.created"
    EST_SIMPLEENROLL: ClassVar[str] = "est.simpleenroll"
    # Add more as you implement them:
    # DEVICE_UPDATED: ClassVar[str] = "device.updated"
    # ENROLLMENT_CREATED: ClassVar[str] = "enrollment.created"
