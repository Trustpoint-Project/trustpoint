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

    COMPLETE_HSM:
        The HSM must perform the complete digest+sign operation using an exact
        PKCS#11 mechanism such as CKM_SHA256_RSA_PKCS or CKM_ECDSA_SHA256.

    ALLOW_SOFTWARE_HASH:
        Trustpoint may hash or prepare the payload in software and then invoke
        a raw HSM signing mechanism such as CKM_RSA_PKCS or CKM_ECDSA.
    """

    COMPLETE_HSM = 'complete_hsm'
    ALLOW_SOFTWARE_HASH = 'allow_software_hash'


@dataclass(frozen=True, slots=True)
class KeyPolicy:
    """Policy attached to backend-managed keys."""

    extractable: bool = False
    ephemeral: bool = False
    signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_HSM
    usages: frozenset[KeyUsage] = field(
        default_factory=lambda: frozenset({KeyUsage.SIGN, KeyUsage.VERIFY}),
    )

    @classmethod
    def managed_signing_key(
        cls,
        *,
        signing_execution_mode: SigningExecutionMode = SigningExecutionMode.COMPLETE_HSM,
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
