"""Security-policy authorization checks for PKI objects (CAs and certificates)."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

from trustpoint_core.oid import AlgorithmIdentifier, PublicKeyAlgorithmOid

from management.models import SecurityConfig
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
            # No certificate yet (e.g. pending remote CA); nothing to check.
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
            # No limit configured.
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
        """Check the CA certificate's RSA key size against the policy minimum."""
        cert_model: CertificateModel | None = ca.ca_certificate_model
        if cert_model is None:
            self.logger.debug(
                '_RsaMinimumKeySizeStrategy: CA "%s" has no certificate yet; skipping.',
                ca.unique_name,
            )
            return

        if cert_model.spki_algorithm_oid != PublicKeyAlgorithmOid.RSA.dotted_string:
            # Not an RSA certificate — strategy not applicable.
            self.logger.debug(
                '_RsaMinimumKeySizeStrategy: CA "%s" uses %s (not RSA); skipping.',
                ca.unique_name,
                cert_model.spki_algorithm_oid,
            )
            return

        min_size: int | None = cfg.rsa_minimum_key_size
        if min_size is None:
            msg = (
                f'CA "{ca.unique_name}" uses an RSA key, but RSA is not permitted '
                f'by the active security policy.'
            )
            self.logger.warning('_RsaMinimumKeySizeStrategy: %s', msg)
            raise ValueError(msg)

        if min_size == 0:
            self.logger.debug(
                '_RsaMinimumKeySizeStrategy: CA "%s" — no minimum key size enforced; check passed.',
                ca.unique_name,
            )
            return

        key_size: int = cert_model.spki_key_size
        if key_size < min_size:
            msg = (
                f'CA "{ca.unique_name}" has an RSA key of {key_size} bits, which is below the '
                f'policy minimum of {min_size} bits.'
            )
            self.logger.warning('_RsaMinimumKeySizeStrategy: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            '_RsaMinimumKeySizeStrategy: CA "%s" RSA key %d bits >= min %d bits; check passed.',
            ca.unique_name,
            key_size,
            min_size,
        )


class _NotPermittedEccCurvesStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects CA certificates whose ECC curve OID appears in :attr:`SecurityConfig.not_permitted_ecc_curve_oids`."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Check the CA certificate's ECC curve against the policy block-list."""
        cert_model: CertificateModel | None = ca.ca_certificate_model
        if cert_model is None:
            self.logger.debug(
                '_NotPermittedEccCurvesStrategy: CA "%s" has no certificate yet; skipping.',
                ca.unique_name,
            )
            return

        if cert_model.spki_algorithm_oid != PublicKeyAlgorithmOid.ECC.dotted_string:
            self.logger.debug(
                '_NotPermittedEccCurvesStrategy: CA "%s" uses %s (not ECC); skipping.',
                ca.unique_name,
                cert_model.spki_algorithm_oid,
            )
            return

        not_permitted: list[str] = cfg.not_permitted_ecc_curve_oids or []
        if not not_permitted:
            self.logger.debug(
                '_NotPermittedEccCurvesStrategy: no ECC curves blocked; skipping.',
            )
            return

        curve_oid: str = cert_model.spki_ec_curve_oid
        if not curve_oid:
            self.logger.debug(
                '_NotPermittedEccCurvesStrategy: CA "%s" has no curve OID recorded; skipping.',
                ca.unique_name,
            )
            return

        if curve_oid in not_permitted:
            msg = (
                f'CA "{ca.unique_name}" uses ECC curve OID {curve_oid!r}, which is not permitted '
                f'by the active security policy.'
            )
            self.logger.warning('_NotPermittedEccCurvesStrategy: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            '_NotPermittedEccCurvesStrategy: CA "%s" curve OID %r is permitted; check passed.',
            ca.unique_name,
            curve_oid,
        )


class _NotPermittedSignatureAlgorithmsStrategy(PkiCheckStrategy, LoggerMixin):
    """Rejects CA certificates whose signature hash algorithm appears in the policy block-list."""

    def check(self, ca: CaModel, cfg: SecurityConfig) -> None:
        """Check the CA certificate's signature hash algorithm against the policy block-list."""
        cert_model: CertificateModel | None = ca.ca_certificate_model
        if cert_model is None:
            self.logger.debug(
                '_NotPermittedSignatureAlgorithmsStrategy: CA "%s" has no certificate yet; skipping.',
                ca.unique_name,
            )
            return

        not_permitted: list[str] = cfg.not_permitted_signature_algorithm_oids or []
        if not not_permitted:
            self.logger.debug(
                '_NotPermittedSignatureAlgorithmsStrategy: no signature algorithms blocked; skipping.',
            )
            return

        sig_oid: str = cert_model.signature_algorithm_oid
        try:
            algo_id = AlgorithmIdentifier.from_dotted_string(sig_oid)
        except ValueError:
            # Unknown algorithm identifier — cannot check; log and skip.
            self.logger.debug(
                '_NotPermittedSignatureAlgorithmsStrategy: CA "%s" has unknown signature algorithm OID %r; skipping.',
                ca.unique_name,
                sig_oid,
            )
            return

        hash_algo = algo_id.hash_algorithm
        if hash_algo is None:
            self.logger.debug(
                '_NotPermittedSignatureAlgorithmsStrategy: CA "%s" algorithm %r has no associated hash; skipping.',
                ca.unique_name,
                algo_id.name,
            )
            return

        hash_oid: str = hash_algo.dotted_string
        if hash_oid in not_permitted:
            msg = (
                f'CA "{ca.unique_name}" is signed with {algo_id.name} '
                f'(hash OID {hash_oid!r}), which is not permitted by the active security policy.'
            )
            self.logger.warning('_NotPermittedSignatureAlgorithmsStrategy: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            '_NotPermittedSignatureAlgorithmsStrategy: CA "%s" signature hash %r is permitted; check passed.',
            ca.unique_name,
            hash_algo.name,
        )

class PkiSecurityAuthorization(LoggerMixin):
    """Runs all PKI security-policy checks against the active :class:`~management.models.SecurityConfig`."""

    def __init__(self, strategies: list[PkiCheckStrategy] | None = None) -> None:
        """Initialise with the default strategy set, or a custom list for testing."""
        self._strategies: list[PkiCheckStrategy] = strategies or [
            _AllowSelfSignedCaStrategy(),
            _MaxCrlValidityStrategy(),
            _RsaMinimumKeySizeStrategy(),
            _NotPermittedEccCurvesStrategy(),
            _NotPermittedSignatureAlgorithmsStrategy(),
        ]

    def check(self, ca: CaModel) -> None:
        """Run all PKI policy checks against *ca*."""
        try:
            cfg: SecurityConfig = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            self.logger.warning(
                'PkiSecurityAuthorization: no SecurityConfig found; skipping all checks for CA "%s".',
                ca.unique_name,
            )
            return
        except SecurityConfig.MultipleObjectsReturned:
            cfg = SecurityConfig.objects.first()  # type: ignore[assignment]
            self.logger.warning(
                'PkiSecurityAuthorization: multiple SecurityConfig rows found; using first for CA "%s".',
                ca.unique_name,
            )

        for strategy in self._strategies:
            strategy.check(ca, cfg)

        self.logger.debug(
            'PkiSecurityAuthorization: all checks passed for CA "%s".',
            ca.unique_name,
        )
