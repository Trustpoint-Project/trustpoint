# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Security Configuration Model."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar, TypedDict, cast

from django.core.exceptions import ValidationError
from django.core.validators import MinValueValidator
from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import HashAlgorithm, HmacAlgorithm, NamedCurve, PublicKeyAlgorithmOid

from management.security_env import effective_security_defaults, parse_security_restrictions
from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from pki.security_policy import (
    CryptographicPolicy,
    evaluate_cryptographic_policy,
    stored_public_key_facts,
    stored_signature_facts,
)
from pki.util.keys import AutoGenPkiKeyAlgorithm

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models.ca import CaModel


class _SecurityModeDefaults(TypedDict):
    """Typed structure for per-mode security defaults."""

    rsa_minimum_key_size: int | None
    not_permitted_ecc_curve_oids: list[str]
    not_permitted_mldsa_variant_oids: list[str]
    not_permitted_signature_algorithm_oids: list[str]
    max_cert_validity_days: int | None
    max_crl_validity_days: int | None
    credential_ttl_seconds: int | None
    allow_user_defined_device_secrets: bool
    allow_ca_issuance: bool
    allow_auto_gen_pki: bool
    allow_self_signed_ca: bool
    allow_imported_private_keys: bool
    permitted_cmp_hmac_algorithms: list[str]
    permitted_no_onboarding_pki_protocols: list[int]
    permitted_onboarding_protocols: list[int]


def default_cmp_hmac_algorithms() -> list[str]:
    """Return the default CMP MAC allowlist without shared mutable state."""
    return [algorithm.dotted_string for algorithm in (
        HmacAlgorithm.HMAC_SHA256, HmacAlgorithm.HMAC_SHA384, HmacAlgorithm.HMAC_SHA512,
    )]


class SecurityConfig(models.Model):
    """Security Configuration model.

    Stores the active security level together with all security thresholds for that level:

    * :attr:`rsa_minimum_key_size` — minimum acceptable RSA key size in bits
      (``0`` = any RSA key size allowed, ``None`` = RSA not allowed).
    * :attr:`not_permitted_ecc_curve_oids` — JSON list of :class:`trustpoint_core.oid.NamedCurve`
      OID strings that are not permitted at the current level.
    * :attr:`not_permitted_signature_algorithm_oids` — JSON list of
      :class:`trustpoint_core.oid.HashAlgorithm` OID strings that are not permitted.
    * :attr:`max_cert_validity_days` — maximum certificate validity in days (``None`` = no limit).
    * :attr:`max_crl_validity_days` — maximum CRL validity in days (``None`` = no limit).
    * :attr:`allow_ca_issuance` — whether BasicConstraints ca=True is permitted in issued certs.
    * :attr:`allow_auto_gen_pki` — whether auto-generated PKI may be enabled.
    * :attr:`allow_self_signed_ca` — whether self-signed CAs with credentials are allowed.
    * :attr:`permitted_no_onboarding_pki_protocols` — JSON list of allowed
      :class:`onboarding.models.NoOnboardingPkiProtocol` integer values.
    * :attr:`permitted_onboarding_protocols` — JSON list of allowed
      :class:`onboarding.models.OnboardingProtocol` integer values.

    Calling :meth:`apply_security_settings` applies the mode defaults onto this instance.
    """

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

        LAB = '0', _('Lab / Custom')
        BROWNFIELD = '1', _('Brownfield Compatible')
        INDUSTRIAL = '2', _('Industrial Standard')
        HARDENED = '3', _('Hardened Production')
        CRITICAL = '4', _('Critical Infrastructure')

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

    class CmpHmacAlgorithmChoices(models.TextChoices):
        """HMAC algorithms supported by CMP authentication and response protection."""

        MD5 = HmacAlgorithm.HMAC_MD5.dotted_string, _('HMAC-MD5')
        SHA1 = HmacAlgorithm.HMAC_SHA1.dotted_string, _('HMAC-SHA1')
        SHA224 = HmacAlgorithm.HMAC_SHA224.dotted_string, _('HMAC-SHA224')
        SHA256 = HmacAlgorithm.HMAC_SHA256.dotted_string, _('HMAC-SHA256')
        SHA384 = HmacAlgorithm.HMAC_SHA384.dotted_string, _('HMAC-SHA384')
        SHA512 = HmacAlgorithm.HMAC_SHA512.dotted_string, _('HMAC-SHA512')
        SHA3_224 = HmacAlgorithm.HMAC_SHA3_224.dotted_string, _('HMAC-SHA3-224')
        SHA3_256 = HmacAlgorithm.HMAC_SHA3_256.dotted_string, _('HMAC-SHA3-256')
        SHA3_384 = HmacAlgorithm.HMAC_SHA3_384.dotted_string, _('HMAC-SHA3-384')
        SHA3_512 = HmacAlgorithm.HMAC_SHA3_512.dotted_string, _('HMAC-SHA3-512')

    class MlDsaVariantChoices(models.TextChoices):
        """Selectable ML-DSA variants from :class:`trustpoint_core.oid.PublicKeyAlgorithmOid`."""

        MLDSA44 = PublicKeyAlgorithmOid.ML_DSA_44.dotted_string, _('ML-DSA-44')
        MLDSA65 = PublicKeyAlgorithmOid.ML_DSA_65.dotted_string, _('ML-DSA-65')
        MLDSA87 = PublicKeyAlgorithmOid.ML_DSA_87.dotted_string, _('ML-DSA-87')

    # ------------------------------------------------------------------
    # Model fields
    # ------------------------------------------------------------------

    security_mode = models.CharField(
        max_length=6,
        choices=SecurityModeChoices,
        default=SecurityModeChoices.BROWNFIELD,
    )

    auto_gen_pki = models.BooleanField(default=False)
    auto_gen_pki_key_algorithm = models.CharField(
        max_length=24,
        choices=AutoGenPkiKeyAlgorithm,
        default=AutoGenPkiKeyAlgorithm.RSA2048,
    )

    # -- Key constraints --------------------------------------------------

    rsa_minimum_key_size = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=2048,
        help_text=_(
            'Minimum RSA key size in bits that certificates must meet. Set to null to disallow RSA entirely.',
        ),
    )

    not_permitted_ecc_curve_oids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of ECC curve OIDs (from trustpoint_core.oid.NamedCurve) '
            'not permitted at the current security level.',
        ),
    )

    not_permitted_mldsa_variant_oids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of ML-DSA variant OIDs (from trustpoint_core.oid.PublicKeyAlgorithmOid) '
            'not permitted at the current security level.',
        ),
    )

    not_permitted_signature_algorithm_oids = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of hash algorithm OIDs (from trustpoint_core.oid.HashAlgorithm) '
            'not permitted at the current security level.',
        ),
    )

    # -- Certificate / CRL validity ---------------------------------------

    max_cert_validity_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=_(
            'Maximum certificate validity period in days. '
            'Set to null for no limit.',
        ),
    )

    max_crl_validity_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=_(
            'Maximum CRL validity period in days. '
            'Set to null for no limit.',
        ),
    )

    credential_ttl_seconds = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        validators=[MinValueValidator(1)],
        help_text=_(
            'Default lifetime in seconds for onboarding credentials and SCEP challenges. Blank means no expiry.'
        ),
    )

    allow_user_defined_device_secrets = models.BooleanField(
        default=False,
        help_text=_('Allow custom device enrollment secrets. Requires an unset credential TTL.'),
    )

    # -- Certificate policy flags -----------------------------------------

    allow_ca_issuance = models.BooleanField(
        default=False,
        help_text=_('Allow issuance of certificates with BasicConstraints ca=True.'),
    )

    allow_auto_gen_pki = models.BooleanField(
        default=False,
        help_text=_('Allow enabling the auto-generated PKI feature.'),
    )

    allow_self_signed_ca = models.BooleanField(
        default=False,
        help_text=_('Allow self-signed CAs to be imported with credentials.'),
    )

    allow_imported_private_keys = models.BooleanField(
        default=False,
        help_text=_(
            'Allow existing private-key credentials to be imported. Imported keys require '
            'PKCS#11-backed application-secret protection and are stored encrypted in the database.',
        ),
    )

    permitted_cmp_hmac_algorithms = models.JSONField(
        default=default_cmp_hmac_algorithms,
        blank=True,
        verbose_name=_('Permitted CMP HMAC algorithms'),
        help_text=_(
            'Select the HMAC algorithms accepted for CMP shared-secret protection. '
            'An empty selection disables CMP shared-secret authentication. '
            'OpenSSL uses HMAC-SHA1 by default.',
        ),
    )

    # -- Protocol allow-lists (stored as JSON lists of integer values) -----

    permitted_no_onboarding_pki_protocols = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of allowed NoOnboardingPkiProtocol integer values '
            '(bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, '
            'MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64).',
        ),
    )

    permitted_onboarding_protocols = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of allowed OnboardingProtocol integer values '
            '(MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, '
            'EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7, '
            'REST_USERNAME_PASSWORD=8, AGENT=9).',
        ),
    )

    # ------------------------------------------------------------------
    # Default configurations keyed by mode
    # ------------------------------------------------------------------

    #: All implemented OnboardingProtocol values
    _ALL_ONBOARDING_PROTOCOLS: ClassVar[list[int]] = [
        protocol.value for protocol in OnboardingProtocol if protocol is not OnboardingProtocol.BRSKI
    ]
    #: All implemented OnboardingProtocol values except MANUAL
    _ONBOARDING_PROTOCOLS_NO_MANUAL: ClassVar[list[int]] = [
        protocol.value for protocol in OnboardingProtocol
        if protocol not in (OnboardingProtocol.MANUAL, OnboardingProtocol.BRSKI)
    ]

    _MODE_DEFAULTS: ClassVar[dict[str, _SecurityModeDefaults]] = {
        # ----------------------------------------------------------------
        # Lab / Development
        # ----------------------------------------------------------------
        SecurityModeChoices.LAB: {
            'rsa_minimum_key_size': 0,  # any RSA key size allowed
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_mldsa_variant_oids': [],
            'not_permitted_signature_algorithm_oids': [],
            'max_cert_validity_days': None,  # no limit
            'max_crl_validity_days': None,  # no limit
            'credential_ttl_seconds': None,
            'allow_user_defined_device_secrets': False,
            'allow_ca_issuance': True,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'allow_imported_private_keys': True,
            'permitted_cmp_hmac_algorithms': [CmpHmacAlgorithmChoices.SHA1, *default_cmp_hmac_algorithms()],
            # CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64
            'permitted_no_onboarding_pki_protocols': [1, 4, 16, 32, 64],
            'permitted_onboarding_protocols': _ALL_ONBOARDING_PROTOCOLS,
        },
        # ----------------------------------------------------------------
        # Brownfield Compatible
        # ----------------------------------------------------------------
        SecurityModeChoices.BROWNFIELD: {
            'rsa_minimum_key_size': 1024,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_mldsa_variant_oids': [],
            'not_permitted_signature_algorithm_oids': [],
            'max_cert_validity_days': 1825,  # 5 years
            'max_crl_validity_days': 365,
            'credential_ttl_seconds': None,
            'allow_user_defined_device_secrets': False,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'allow_imported_private_keys': True,
            'permitted_cmp_hmac_algorithms': [CmpHmacAlgorithmChoices.SHA1, *default_cmp_hmac_algorithms()],
            # CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64
            'permitted_no_onboarding_pki_protocols': [1, 4, 16, 32, 64],
            'permitted_onboarding_protocols': _ALL_ONBOARDING_PROTOCOLS,
        },
        # ----------------------------------------------------------------
        # Industrial Standard
        # ----------------------------------------------------------------
        SecurityModeChoices.INDUSTRIAL: {
            'rsa_minimum_key_size': 3072,
            'not_permitted_ecc_curve_oids': [
                NamedCurveChoices.SECP192R1,
                NamedCurveChoices.SECP224R1,
            ],
            'not_permitted_mldsa_variant_oids': [],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
            ],
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 180,
            'credential_ttl_seconds': None,
            'allow_user_defined_device_secrets': False,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'allow_imported_private_keys': True,
            'permitted_cmp_hmac_algorithms': default_cmp_hmac_algorithms(),
            # CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16, REST_USERNAME_PASSWORD=32, SCEP=64
            'permitted_no_onboarding_pki_protocols': [1, 4, 16, 32, 64],
            'permitted_onboarding_protocols': _ALL_ONBOARDING_PROTOCOLS,
        },
        # ----------------------------------------------------------------
        # Hardened Production
        # ----------------------------------------------------------------
        SecurityModeChoices.HARDENED: {
            'rsa_minimum_key_size': 4096,
            'not_permitted_ecc_curve_oids': [
                NamedCurveChoices.SECP192R1,
                NamedCurveChoices.SECP224R1,
                NamedCurveChoices.SECP256K1,
            ],
            'not_permitted_mldsa_variant_oids': [],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
            ],
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 90,
            'credential_ttl_seconds': 600,
            'allow_user_defined_device_secrets': False,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'allow_imported_private_keys': False,
            'permitted_cmp_hmac_algorithms': default_cmp_hmac_algorithms(),
            'permitted_no_onboarding_pki_protocols': [1, 4],  # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD only
            'permitted_onboarding_protocols': _ONBOARDING_PROTOCOLS_NO_MANUAL,
        },
        # ----------------------------------------------------------------
        # Critical Infrastructure
        # ----------------------------------------------------------------
        SecurityModeChoices.CRITICAL: {
            'rsa_minimum_key_size': None,
            'not_permitted_ecc_curve_oids': [
                NamedCurveChoices.SECP192R1,
                NamedCurveChoices.SECP224R1,
                NamedCurveChoices.SECP256K1,
                NamedCurveChoices.SECP256R1,
                NamedCurveChoices.BRAINPOOLP256R1,
            ],
            'not_permitted_mldsa_variant_oids': [],
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
                HashAlgorithmChoices.SHA256,
            ],
            'max_cert_validity_days': 180,
            'max_crl_validity_days': 90,
            'credential_ttl_seconds': 600,
            'allow_user_defined_device_secrets': False,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'allow_imported_private_keys': False,
            'permitted_cmp_hmac_algorithms': default_cmp_hmac_algorithms(),
            'permitted_no_onboarding_pki_protocols': [1, 4],  # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD only
            'permitted_onboarding_protocols': _ONBOARDING_PROTOCOLS_NO_MANUAL,
        },
    }

    class Meta:
        """Enforce the custom-secret policy for every database writer."""

        constraints: ClassVar[list[models.BaseConstraint]] = [models.CheckConstraint(
            condition=models.Q(allow_user_defined_device_secrets=False) | models.Q(credential_ttl_seconds__isnull=True),
            name='custom_device_secrets_require_no_ttl',
        )]

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Validate policy on direct configuration writes as well as forms."""
        self.clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Reject conflicting effective policy, including mode restrictions."""
        super().clean()
        if self.allow_user_defined_device_secrets:
            effective = effective_security_defaults(self.security_mode)

            if parse_security_restrictions().allow_user_defined_device_secrets is False:
                raise ValidationError({
                    'allow_user_defined_device_secrets': _('Custom secrets are disabled by deployment policy.'),
                })
            if self.credential_ttl_seconds is not None or effective['credential_ttl_seconds'] is not None:
                raise ValidationError({
                    'allow_user_defined_device_secrets':
                        _('Custom device secrets require an unset credential TTL and a mode permitting no expiry.'),
                })

    def apply_security_settings(self, *, save: bool = True) -> None:
        """Reset all thresholds to the defaults for the current security mode."""
        if not self.security_mode:
            return

        defaults = self._MODE_DEFAULTS.get(self.security_mode)
        if defaults is None:
            msg = f'No defaults defined for security mode: {self.security_mode}'
            raise ValueError(msg)

        self.rsa_minimum_key_size = defaults['rsa_minimum_key_size']
        self.not_permitted_ecc_curve_oids = list(defaults['not_permitted_ecc_curve_oids'])
        self.not_permitted_mldsa_variant_oids = list(defaults['not_permitted_mldsa_variant_oids'])
        self.not_permitted_signature_algorithm_oids = list(defaults['not_permitted_signature_algorithm_oids'])
        self.max_cert_validity_days = defaults['max_cert_validity_days']
        self.max_crl_validity_days = defaults['max_crl_validity_days']
        self.credential_ttl_seconds = defaults['credential_ttl_seconds']
        self.allow_ca_issuance = defaults['allow_ca_issuance']
        self.allow_auto_gen_pki = defaults['allow_auto_gen_pki']
        self.allow_self_signed_ca = defaults['allow_self_signed_ca']
        self.allow_imported_private_keys = defaults['allow_imported_private_keys']
        self.permitted_cmp_hmac_algorithms = list(defaults['permitted_cmp_hmac_algorithms'])
        self.permitted_no_onboarding_pki_protocols = list(defaults['permitted_no_onboarding_pki_protocols'])
        self.permitted_onboarding_protocols = list(defaults['permitted_onboarding_protocols'])
        if save:
            self.save(
                update_fields=[
                    'rsa_minimum_key_size',
                    'not_permitted_ecc_curve_oids',
                    'not_permitted_mldsa_variant_oids',
                    'not_permitted_signature_algorithm_oids',
                    'max_cert_validity_days',
                    'max_crl_validity_days',
                    'credential_ttl_seconds',
                    'allow_ca_issuance',
                    'allow_auto_gen_pki',
                    'allow_self_signed_ca',
                    'allow_imported_private_keys',
                    'permitted_cmp_hmac_algorithms',
                    'permitted_no_onboarding_pki_protocols',
                    'permitted_onboarding_protocols',
                ]
            )

    @classmethod
    def get_settings_preview_json(cls) -> str:
        """Return a JSON string of each mode's display-friendly threshold values for the settings JS."""
        ecc_labels = dict(cls.NamedCurveChoices.choices)
        sig_labels = dict(cls.HashAlgorithmChoices.choices)
        mldsa_labels = dict(cls.MlDsaVariantChoices.choices)

        no_onboarding_labels: dict[int, str] = {c.value: str(c.label) for c in NoOnboardingPkiProtocol}
        onboarding_labels: dict[int, str] = {c.value: str(c.label) for c in OnboardingProtocol}

        preview: dict[str, dict[str, object]] = {}
        for mode, defaults in cls._MODE_DEFAULTS.items():
            preview[mode] = {
                'rsa_minimum_key_size': defaults['rsa_minimum_key_size'],
                'not_permitted_ecc_curves': [
                    str(ecc_labels.get(oid, oid)) for oid in defaults['not_permitted_ecc_curve_oids']
                ],
                'not_permitted_mldsa_variants': [
                    str(mldsa_labels.get(oid, oid)) for oid in defaults['not_permitted_mldsa_variant_oids']
                ],
                'not_permitted_signature_algorithms': [
                    str(sig_labels.get(oid, oid)) for oid in defaults['not_permitted_signature_algorithm_oids']
                ],
                'max_cert_validity_days': defaults['max_cert_validity_days'],
                'max_crl_validity_days': defaults['max_crl_validity_days'],
                'credential_ttl_seconds': defaults['credential_ttl_seconds'],
                'allow_user_defined_device_secrets': defaults['allow_user_defined_device_secrets'],
                'allow_ca_issuance': defaults['allow_ca_issuance'],
                'allow_auto_gen_pki': defaults['allow_auto_gen_pki'],
                'allow_self_signed_ca': defaults['allow_self_signed_ca'],
                'permitted_cmp_hmac_algorithms': defaults['permitted_cmp_hmac_algorithms'],
                'permitted_no_onboarding_pki_protocols': [
                    no_onboarding_labels.get(v, v) for v in defaults['permitted_no_onboarding_pki_protocols']
                ],
                'permitted_onboarding_protocols': [
                    onboarding_labels.get(v, v) for v in defaults['permitted_onboarding_protocols']
                ],
                'raw_permitted_no_onboarding_pki_protocols': defaults['permitted_no_onboarding_pki_protocols'],
                'raw_permitted_onboarding_protocols': defaults['permitted_onboarding_protocols'],
            }
        return json.dumps(preview)

    def check_policy_transition(
        self, requested_policy: _SecurityModeDefaults, target_mode: str,
    ) -> list[str]:
        """Check existing data against an already-built requested policy."""
        mode_label = str(self.SecurityModeChoices(target_mode).label)
        violations: list[str] = []

        from devices.models import DeviceModel  # noqa: PLC0415
        from pki.models.ca import CaModel  # noqa: PLC0415

        violations.extend(self._check_auto_gen_pki(requested_policy, mode_label))
        violations.extend(self._check_self_signed_cas(requested_policy, mode_label, CaModel))
        violations.extend(self._check_cryptographic_policy(requested_policy, mode_label, CaModel))
        violations.extend(self._check_crl_validity(requested_policy, mode_label, CaModel))
        violations.extend(self._check_no_onboarding_protocols(requested_policy, mode_label, CaModel, DeviceModel))
        violations.extend(self._check_onboarding_protocols(requested_policy, mode_label, DeviceModel))
        return violations

    def check_mode_transition(self, target_mode: str) -> list[str]:
        """Check whether existing data satisfies the effective policy for *target_mode*."""
        defaults = cast('_SecurityModeDefaults', effective_security_defaults(target_mode))
        return self.check_policy_transition(defaults, target_mode)

    # ------------------------------------------------------------------
    # Private helpers — one method per check group
    # ------------------------------------------------------------------

    def _check_auto_gen_pki(self, defaults: _SecurityModeDefaults, mode_label: str) -> list[str]:
        """Return a violation if auto-generated PKI is enabled but not permitted in the target mode."""
        if not defaults['allow_auto_gen_pki'] and self.auto_gen_pki:
            return [
                str(
                    _(
                        'Auto-generated PKI is currently enabled but is not permitted in %(mode)s.',
                    )
                    % {'mode': mode_label}
                )
            ]
        return []

    @staticmethod
    def _check_self_signed_cas(
        defaults: _SecurityModeDefaults,
        mode_label: str,
        ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for self-signed issuing CAs when the target mode forbids them."""
        if defaults['allow_self_signed_ca']:
            return []
        names = ca_model.objects.filter(
            credential__certificate__is_self_signed=True,
        ).values_list('unique_name', flat=True)
        return [
            str(
                _(
                    'Issuing CA "%(ca)s" has a self-signed certificate, which is not permitted in %(mode)s.',
                )
                % {'ca': n, 'mode': mode_label}
            )
            for n in names
        ]

    @staticmethod
    def _check_cryptographic_policy(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Evaluate existing CA material against the requested immutable policy."""
        policy = CryptographicPolicy.from_mapping(defaults)
        violations: list[str] = []
        cas = ca_model.objects.filter(credential__certificate__isnull=False).select_related('credential__certificate')
        for ca in cas:
            certificate = ca.ca_certificate_model
            if certificate is None:
                continue
            failures = evaluate_cryptographic_policy(
                policy, key=stored_public_key_facts(certificate), signature=stored_signature_facts(certificate),
            )
            violations.extend(
                str(_('Issuing CA "%(ca)s": %(violation)s Requested mode: %(mode)s.') % {
                    'ca': ca.unique_name, 'violation': failure.message, 'mode': mode_label,
                })
                for failure in failures
            )
        return violations

    @staticmethod
    def _check_crl_validity(
        defaults: _SecurityModeDefaults,
        mode_label: str,
        ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for CAs whose CRL validity exceeds the target mode maximum."""
        max_days: int | None = defaults['max_crl_validity_days']
        if max_days is None:
            return []
        max_hours = float(max_days) * 24
        rows = ca_model.objects.filter(
            crl_validity_hours__gt=max_hours,
        ).values_list('unique_name', 'crl_validity_hours')
        return [
            str(
                _(
                    'Issuing CA "%(ca)s" has a CRL validity of %(hours).2f hours (%(days).1f days), '
                    'exceeding the maximum of %(max_days)d days in %(mode)s.',
                )
                % {'ca': n, 'hours': h, 'days': h / 24, 'max_days': max_days, 'mode': mode_label}
            )
            for n, h in rows
        ]

    @staticmethod
    def _check_no_onboarding_protocols(
        defaults: _SecurityModeDefaults,
        mode_label: str,
        ca_model: type[CaModel],
        device_model: type[DeviceModel],
    ) -> list[str]:
        """Return violations for CAs/devices using a no-onboarding protocol blocked by the target mode."""
        permitted: list[int] = defaults['permitted_no_onboarding_pki_protocols']
        proto_labels: dict[int, str] = {c.value: str(c.label) for c in NoOnboardingPkiProtocol}
        violations: list[str] = []
        for proto in NoOnboardingPkiProtocol:
            if proto.value in permitted:
                continue
            label = proto_labels.get(proto.value, str(proto.value))
            for ca_name, bitmask in ca_model.objects.filter(
                no_onboarding_config__isnull=False,
            ).values_list('unique_name', 'no_onboarding_config__pki_protocols'):
                if bitmask is not None and (bitmask & proto.value) == proto.value:
                    violations.append(
                        str(
                            _(
                                'Issuing CA "%(ca)s" uses no-onboarding protocol "%(protocol)s", '
                                'which is not permitted in %(mode)s.',
                            )
                            % {'ca': ca_name, 'protocol': label, 'mode': mode_label}
                        )
                    )
            for dev_name, bitmask in device_model.objects.filter(
                no_onboarding_config__isnull=False,
            ).values_list('common_name', 'no_onboarding_config__pki_protocols'):
                if bitmask is not None and (bitmask & proto.value) == proto.value:
                    violations.append(
                        str(
                            _(
                                'Device "%(device)s" uses no-onboarding protocol "%(protocol)s", '
                                'which is not permitted in %(mode)s.',
                            )
                            % {'device': dev_name, 'protocol': label, 'mode': mode_label}
                        )
                    )
        return violations

    @staticmethod
    def _check_onboarding_protocols(
        defaults: _SecurityModeDefaults,
        mode_label: str,
        device_model: type[DeviceModel],
    ) -> list[str]:
        """Return violations for devices using an onboarding protocol blocked by the target mode."""
        permitted: list[int] = defaults['permitted_onboarding_protocols']
        proto_labels: dict[int, str] = {c.value: str(c.label) for c in OnboardingProtocol}
        rows = (
            device_model.objects.filter(
                onboarding_config__isnull=False,
            )
            .exclude(
                onboarding_config__onboarding_protocol__in=permitted,
            )
            .values_list('common_name', 'onboarding_config__onboarding_protocol')
        )
        return [
            str(
                _(
                    'Device "%(device)s" uses onboarding protocol "%(protocol)s", which is not permitted in %(mode)s.',
                )
                % {'device': n, 'protocol': proto_labels.get(p, str(p)), 'mode': mode_label}
            )
            for n, p in rows
        ]
