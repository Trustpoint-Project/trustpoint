"""Key policy types for the redesigned crypto layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Self


class KeyUsage(str, Enum):
    """Normalized key usages understood by the backend."""

    SIGN = 'sign'
    VERIFY = 'verify'
    ENCRYPT = 'encrypt'
    DECRYPT = 'decrypt'
    WRAP = 'wrap'
    UNWRAP = 'unwrap'
    CERTIFICATE_SIGN = 'certificate_sign'
    CRL_SIGN = 'crl_sign'


@dataclass(frozen=True, slots=True)
class KeyPolicy:
    """Policy attached to backend-managed keys."""

    extractable: bool = False
    ephemeral: bool = False
    usages: frozenset[KeyUsage] = field(
        default_factory=lambda: frozenset({KeyUsage.SIGN, KeyUsage.VERIFY}),
    )

    @classmethod
    def managed_signing_key(cls) -> Self:
        """Build the default policy for long-lived managed signing keys."""
        return cls(
            extractable=False,
            ephemeral=False,
            usages=frozenset(
                {
                    KeyUsage.SIGN,
                    KeyUsage.VERIFY,
                    KeyUsage.CERTIFICATE_SIGN,
                    KeyUsage.CRL_SIGN,
                },
            ),
        )

    @property
    def can_sign(self) -> bool:
        """Whether this policy allows private-key signing operations."""
        signing_usages = {KeyUsage.SIGN, KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN}
        return bool(self.usages.intersection(signing_usages))
