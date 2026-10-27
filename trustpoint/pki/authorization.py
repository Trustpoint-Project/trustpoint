# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security-policy authorization checks for PKI objects (CAs and certificates)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

from trustpoint_core.oid import PublicKeyAlgorithmOid

from management.models import SecurityConfig
from pki.security_policy import (
    CryptographicPolicy,
    CryptographicPolicyError,
    enforce_cryptographic_policy,
    stored_public_key_facts,
    stored_signature_facts,
)
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from pki.models.ca import CaModel
    from pki.models.certificate import CertificateModel


class HasCaModel(Protocol):
    """Structural type satisfied by :class:`~pki.models.ca.CaModel`.

    Any object exposing ``ca_certificate_model``, ``is_self_signed_ca``, and
    ``crl_validity_hours`` attributes qualifies.
    """

    @property
    def ca_certificate_model(self) -> CertificateModel | None:
        """Return the :class:`~pki.models.certificate.CertificateModel` for this CA, or ``None``."""

    @property
    def crl_validity_hours(self) -> float:
        """Return the configured CRL validity in hours."""


class PkiCheckStrategy(ABC):
    """Abstract base for a single PKI security-policy check."""

    @abstractmethod
    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Execute the check.

        Args:
            ca:  The :class:`~pki.models.ca.CaModel` being evaluated.
            cfg: The active :class:`~management.models.SecurityConfig` policy.

        Raises:
            ValueError: If the CA violates the policy.
        """


class _AllowSelfSignedCaStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects self-signed CAs when :attr:`SecurityConfig.allow_self_signed_ca` is ``False``."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Check whether the CA's certificate is self-signed and the policy forbids it."""
        if cfg.allow_self_signed_ca:
            return

        cert_model: CertificateModel | None = ca.ca_certificate_model
        if cert_model is None:
            self.logger.debug(
                '_AllowSelfSignedCaStrategy: CA "%s" has no certificate yet; skipping.',
                ca.unique_name,
            )
            return

        if cert_model.is_self_signed:
            msg = (
                f'CA "{ca.unique_name}" uses a self-signed certificate, which is not permitted '
                f'by the active security policy.'
            )
            self.logger.warning('_AllowSelfSignedCaStrategy: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            '_AllowSelfSignedCaStrategy: CA "%s" is not self-signed; check passed.',
            ca.unique_name,
        )


class _MaxCrlValidityStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects a CA's CRL validity setting when it exceeds :attr:`SecurityConfig.max_crl_validity_days`."""

    _HOURS_PER_DAY: int = 24

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Compare the CA's ``crl_validity_hours`` against the policy maximum (converted to hours)."""
        max_days: int | None = cfg.max_crl_validity_days
        if max_days is None:
            self.logger.debug(
                '_MaxCrlValidityStrategy: no max_crl_validity_days set; skipping.',
            )
            return

        ca_validity_hours: float = float(ca.crl_validity_hours)
        max_hours: float = float(max_days) * self._HOURS_PER_DAY

        if ca_validity_hours > max_hours:
            msg = (
                f'CA "{ca.unique_name}" has a CRL validity of {ca_validity_hours:.2f} hours '
                f'({ca_validity_hours / self._HOURS_PER_DAY:.2f} days), which exceeds the policy '
                f'maximum of {max_days} days ({max_hours:.0f} hours).'
            )
            self.logger.warning('_MaxCrlValidityStrategy: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            '_MaxCrlValidityStrategy: CA "%s" CRL validity %.2f h <= max %.0f h; check passed.',
            ca.unique_name,
            ca_validity_hours,
            max_hours,
        )


class _RsaMinimumKeySizeStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects CA certificates that use an RSA key below :attr:`SecurityConfig.rsa_minimum_key_size`."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Delegate RSA validation to the shared evaluator."""
        certificate = ca.ca_certificate_model
        if certificate is not None and certificate.spki_algorithm_oid == PublicKeyAlgorithmOid.RSA.dotted_string:
            enforce_cryptographic_policy(
                CryptographicPolicy(rsa_minimum_key_size=cfg.rsa_minimum_key_size),
                key=stored_public_key_facts(certificate),
            )


class _NotPermittedEccCurvesStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects CA certificates whose ECC curve OID appears in :attr:`SecurityConfig.not_permitted_ecc_curve_oids`."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Delegate ECC validation to the shared evaluator."""
        certificate = ca.ca_certificate_model
        if certificate is not None and certificate.spki_algorithm_oid == PublicKeyAlgorithmOid.ECC.dotted_string:
            enforce_cryptographic_policy(
                CryptographicPolicy(blocked_curve_oids=frozenset(cfg.not_permitted_ecc_curve_oids or [])),
                key=stored_public_key_facts(certificate),
            )


class _NotPermittedSignatureAlgorithmsStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects unknown or explicitly forbidden CA certificate signature algorithms."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Delegate signature and digest validation to the shared evaluator."""
        certificate = ca.ca_certificate_model
        if certificate is not None:
            enforce_cryptographic_policy(
                CryptographicPolicy(blocked_signature_oids=frozenset(cfg.not_permitted_signature_algorithm_oids or [])),
                signature=stored_signature_facts(certificate),
            )


class _CryptographicPolicyStrategy(PkiCheckStrategy, LoggerMixin):
    """Evaluate the complete CA key/signature policy from one immutable snapshot."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Validate existing certificates; pending CAs have no material to evaluate."""
        certificate = ca.ca_certificate_model
        if certificate is None:
            return
        try:
            enforce_cryptographic_policy(
                CryptographicPolicy.from_config(cfg),
                key=stored_public_key_facts(certificate), signature=stored_signature_facts(certificate),
            )
        except CryptographicPolicyError as exc:
            message = f'CA "{ca.unique_name}": {exc}'
            self.logger.warning('PkiSecurityAuthorization: %s', message)
            raise ValueError(message) from exc


class PkiSecurityAuthorization(LoggerMixin):
    """Runs all PKI security-policy checks against the active :class:`~management.models.SecurityConfig`."""

    def __init__(self, strategies: list[PkiCheckStrategy] | None = None) -> None:
        """Initialise with the default strategy set, or a custom list for testing."""
        self._strategies: list[PkiCheckStrategy] = strategies or [
            _AllowSelfSignedCaStrategy(),
            _MaxCrlValidityStrategy(),
            _CryptographicPolicyStrategy(),
        ]

    def check(self, ca: CaModel) -> None:
        """Run all PKI policy checks against *ca* and fail closed on ambiguous policy state."""
        try:
            cfg = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist as exc:
            msg = (
                f'No SecurityConfig is configured; refusing security-policy authorization for CA "{ca.unique_name}".'
            )
            self.logger.exception('PkiSecurityAuthorization: %s', msg)
            raise ValueError(msg) from exc
        except SecurityConfig.MultipleObjectsReturned as exc:
            msg = (
                f'Multiple SecurityConfig rows are configured; refusing security-policy authorization '
                f'for CA "{ca.unique_name}".'
            )
            self.logger.exception('PkiSecurityAuthorization: %s', msg)
            raise ValueError(msg) from exc

        for strategy in self._strategies:
            strategy.check(ca, cfg)

        self.logger.debug(
            'PkiSecurityAuthorization: all checks passed for CA "%s".',
            ca.unique_name,
        )
