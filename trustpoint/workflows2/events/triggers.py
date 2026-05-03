"""Canonical trigger identifiers used by Workflow 2."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class Triggers:
    """Canonical trigger keys for workflows2.

    Use these everywhere instead of string literals.
    """

    DEVICE_CREATED: ClassVar[str] = 'device.created'
    DEVICE_UPDATED: ClassVar[str] = 'device.updated'
    DEVICE_DELETED: ClassVar[str] = 'device.deleted'
    CERTIFICATE_ISSUED: ClassVar[str] = 'certificate.issued'
    CERTIFICATE_REVOKED: ClassVar[str] = 'certificate.revoked'
    CMP_INITIALIZATION: ClassVar[str] = 'cmp.initialization'
    CMP_CERTIFICATION: ClassVar[str] = 'cmp.certification'
    CMP_CERTCONF: ClassVar[str] = 'cmp.certconf'
    EST_SIMPLEENROLL: ClassVar[str] = 'est.simpleenroll'
    EST_SIMPLEREENROLL: ClassVar[str] = 'est.simplereenroll'
    REST_ENROLL: ClassVar[str] = 'rest.enroll'
    REST_REENROLL: ClassVar[str] = 'rest.reenroll'
