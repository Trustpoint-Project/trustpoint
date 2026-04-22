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


class SigningExecutionMode(str, Enum):
    """How Trustpoint is allowed to execute managed-key signing for a key.

    COMPLETE_BACKEND:
        The configured backend must perform the complete digest+sign operation.
        For PKCS#11 that means mechanisms such as CKM_SHA256_RSA_PKCS or
        CKM_ECDSA_SHA256. For software or remote backends it means the backend
        receives the original message and performs hashing and signing itself.

    ALLOW_APPLICATION_HASH:
        Trustpoint may hash or prepare the payload in application code and then
        invoke a raw backend signing operation.
    """

    COMPLETE_BACKEND = 'complete_backend'
    ALLOW_APPLICATION_HASH = 'allow_application_hash'


@dataclass(frozen=True, slots=True)
class KeyPolicy:
    """Policy attached to backend-managed keys."""

    extractable: bool = False
    ephemeral: bool = False
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_BACKEND
    usages: frozenset[KeyUsage] = field(
        default_factory=lambda: frozenset({KeyUsage.SIGN, KeyUsage.VERIFY}),
    )

    @classmethod
    def managed_signing_key(
        cls,
        *,
        signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_BACKEND,
    ) -> Self:
        """Build the default policy for long-lived managed signing keys."""
        return cls(
            extractable=False,
            ephemeral=False,
            signing_execution_mode=signing_execution_mode,
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
