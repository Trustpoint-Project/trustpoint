"""Canonical step type identifiers for Workflow 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class StepTypes:
    """Namespace for supported Workflow 2 step type identifiers."""

    # core steps
    SET: ClassVar[str] = 'set'
    SET_STATUS: ClassVar[str] = 'set_status'
    COMPUTE: ClassVar[str] = 'compute'
    LOGIC: ClassVar[str] = 'logic'
    EMAIL: ClassVar[str] = 'email'
    NOTIFICATION: ClassVar[str] = 'notification'
    WEBHOOK: ClassVar[str] = 'webhook'

    # gated step
    APPROVAL: ClassVar[str] = 'approval'

    @classmethod
    def all(cls) -> set[str]:
        """Return the full set of supported step type identifiers."""
        return {
            cls.SET,
            cls.SET_STATUS,
            cls.COMPUTE,
            cls.LOGIC,
            cls.EMAIL,
            cls.NOTIFICATION,
            cls.WEBHOOK,
            cls.APPROVAL,
        }
