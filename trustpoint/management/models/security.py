"""Security Configuration Model."""
from __future__ import annotations

import json
from typing import ClassVar

from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import HashAlgorithm, NamedCurve

from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityConfig(models.Model):
    """Security Configuration model.

    Stores the active security level together with the three security thresholds
    that belong to it:

    * :attr:`rsa_minimum_key_size` — minimum acceptable RSA key size in bits.
    * :attr:`not_permitted_ecc_curve_oids` — JSON list of :class:`trustpoint_core.oid.NamedCurve`
      OID strings that are not permitted at the current level.
    * :attr:`not_permitted_signature_algorithm_oids` — JSON list of
      :class:`trustpoint_core.oid.HashAlgorithm` OID strings that are not permitted.

    Calling :meth:`apply_security_settings` writes these values into the singleton
    :class:`~management.models.NotificationConfig` so that the rest of the system
    (notification checks, certificate verifiers) can read them from one place.
    """

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

        DEV = '0', _('Testing env')
        LOW = '1', _('Basic')
        MEDIUM = '2', _('Medium')
        HIGH = '3', _('High')
        HIGHEST = '4', _('Highest')

    # ------------------------------------------------------------------
    # Choices derived from trustpoint_core.oid enums
    # ------------------------------------------------------------------

    class NamedCurveChoices(models.TextChoices):
        """Selectable ECC curve OIDs sourced from :class:`trustpoint_core.oid.NamedCurve`."""

        SECP192R1 = NamedCurve.SECP192R1.dotted_string, _('SECP192R1')
        SECP224R1 = NamedCurve.SECP224R1.dotted_string, _('SECP224R1')
        SECP256K1 = NamedCurve.SECP256K1.dotted_string, _('SECP256K1')
        SECP256R1 = NamedCurve.SECP256R1.dotted_string, _('SECP256R1')
        SECP384R1 = NamedCurve.SECP384R1.dotted_string, _('SECP384R1')
        SECP521R1 = NamedCurve.SECP521R1.dotted_string, _('SECP521R1')
        BRAINPOOLP256R1 = NamedCurve.BRAINPOOLP256R1.dotted_string, _('BrainpoolP256R1')
        BRAINPOOLP384R1 = NamedCurve.BRAINPOOLP384R1.dotted_string, _('BrainpoolP384R1')
        BRAINPOOLP512R1 = NamedCurve.BRAINPOOLP512R1.dotted_string, _('BrainpoolP512R1')

    class HashAlgorithmChoices(models.TextChoices):
        """Selectable hash/signature algorithm OIDs from :class:`trustpoint_core.oid.HashAlgorithm`."""

        MD5 = HashAlgorithm.MD5.dotted_string, _('MD5')
        SHA1 = HashAlgorithm.SHA1.dotted_string, _('SHA-1')
        SHA224 = HashAlgorithm.SHA224.dotted_string, _('SHA-224')
        SHA256 = HashAlgorithm.SHA256.dotted_string, _('SHA-256')
        SHA384 = HashAlgorithm.SHA384.dotted_string, _('SHA-384')
        SHA512 = HashAlgorithm.SHA512.dotted_string, _('SHA-512')

    # ------------------------------------------------------------------
    # Model fields
    # ------------------------------------------------------------------

    security_mode = models.CharField(
        max_length=6,
        choices=SecurityModeChoices,
        default=SecurityModeChoices.LOW,
    )

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(
        max_length=24,
        choices=AutoGenPkiKeyAlgorithm,
        default=AutoGenPkiKeyAlgorithm.RSA2048,
    )

    rsa_minimum_key_size = models.PositiveIntegerField(
        default=2048,
        help_text=_('Minimum RSA key size in bits that certificates must meet.'),
    )

    not_permitted_ecc_curve_oids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of ECC curve OIDs (from trustpoint_core.oid.NamedCurve) '
            'not permitted at the current security level.'
        ),
    )

    not_permitted_signature_algorithm_oids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of hash algorithm OIDs (from trustpoint_core.oid.HashAlgorithm) '
            'not permitted at the current security level.'
        ),
    )

    # ------------------------------------------------------------------
    # Default configurations keyed by mode — used by _apply_*_defaults
    # and get_settings_preview_json.
    # ------------------------------------------------------------------

    _MODE_DEFAULTS: ClassVar[dict[str, dict[str, object]]] = {
        SecurityModeChoices.DEV: {
            'rsa_minimum_key_size': 1024,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [],
        },
        SecurityModeChoices.LOW: {
            'rsa_minimum_key_size': 1024,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [],
        },
        SecurityModeChoices.MEDIUM: {
            'rsa_minimum_key_size': 2048,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
            ],
        },
        SecurityModeChoices.HIGH: {
            'rsa_minimum_key_size': 3072,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
            ],
        },
        SecurityModeChoices.HIGHEST: {
            'rsa_minimum_key_size': 4096,
            'not_permitted_ecc_curve_oids': [
                NamedCurveChoices.SECP192R1,
                NamedCurveChoices.SECP224R1,
                NamedCurveChoices.SECP256K1,
            ],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
            ],
        },
    }

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply_security_settings(self) -> None:
        """Reset thresholds to the minimum requirements for the current mode.

        Reads the minimum requirements from :attr:`_MODE_DEFAULTS`, writes them onto
        this instance and saves it, then propagates the values to the singleton
        :class:`~management.models.NotificationConfig` so that notification checks
        and certificate verifiers remain functional.

        :raises ValueError: If :attr:`security_mode` is not a recognised mode.
        """
        if not self.security_mode:
            return

        defaults = self._MODE_DEFAULTS.get(self.security_mode)
        if defaults is None:
            msg = f'No minimum requirements defined for security mode: {self.security_mode}'
            raise ValueError(msg)

        self.rsa_minimum_key_size = defaults['rsa_minimum_key_size']  # type: ignore[assignment]
        self.not_permitted_ecc_curve_oids = list(defaults['not_permitted_ecc_curve_oids'])  # type: ignore[arg-type]
        self.not_permitted_signature_algorithm_oids = list(defaults['not_permitted_signature_algorithm_oids'])  # type: ignore[arg-type]
        self.save(update_fields=[
            'rsa_minimum_key_size',
            'not_permitted_ecc_curve_oids',
            'not_permitted_signature_algorithm_oids',
        ])

    @classmethod
    def get_settings_preview_json(cls) -> str:
        """Return a JSON string of each mode's display-friendly threshold values for the settings JS.

        :returns: JSON-encoded ``{mode_value: {field: display_value, ...}, ...}``.
        """
        ecc_labels = dict(cls.NamedCurveChoices.choices)
        sig_labels = dict(cls.HashAlgorithmChoices.choices)

        preview: dict[str, dict[str, object]] = {}
        for mode, defaults in cls._MODE_DEFAULTS.items():
            preview[mode] = {
                'rsa_minimum_key_size': defaults['rsa_minimum_key_size'],
                'not_permitted_ecc_curves': [
                    str(ecc_labels.get(oid, oid)) for oid in defaults['not_permitted_ecc_curve_oids']  # type: ignore[union-attr]
                ],
                'not_permitted_signature_algorithms': [
                    str(sig_labels.get(oid, oid)) for oid in defaults['not_permitted_signature_algorithm_oids']  # type: ignore[union-attr]
                ],
            }
        return json.dumps(preview)


