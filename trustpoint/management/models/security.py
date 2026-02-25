"""Security Configuration Model."""
from __future__ import annotations

import json
from typing import TYPE_CHECKING, ClassVar, TypedDict

from django.db import models
from django.utils.translation import gettext_lazy as _
from trustpoint_core.oid import AlgorithmIdentifier, HashAlgorithm, NamedCurve, PublicKeyAlgorithmOid

from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from pki.util.keys import AutoGenPkiKeyAlgorithm

if TYPE_CHECKING:
    from devices.models import DeviceModel
    from pki.models.ca import CaModel


class _SecurityModeDefaults(TypedDict):
    """Typed structure for per-mode security defaults."""

    rsa_minimum_key_size: int | None
    not_permitted_ecc_curve_oids: list[str]
    not_permitted_signature_algorithm_oids: list[str]
    max_cert_validity_days: int | None
    max_crl_validity_days: int | None
    allow_ca_issuance: bool
    allow_auto_gen_pki: bool
    allow_self_signed_ca: bool
    require_physical_hsm: bool
    permitted_no_onboarding_pki_protocols: list[int]
    permitted_onboarding_protocols: list[int]


class SecurityConfig(models.Model):
    """Security Configuration model.

    Stores the active security level together with all security thresholds for that level:

    * :attr:`rsa_minimum_key_size` — minimum acceptable RSA key size in bits (``None`` = RSA not allowed).
    * :attr:`not_permitted_ecc_curve_oids` — JSON list of :class:`trustpoint_core.oid.NamedCurve`
      OID strings that are not permitted at the current level.
    * :attr:`not_permitted_signature_algorithm_oids` — JSON list of
      :class:`trustpoint_core.oid.HashAlgorithm` OID strings that are not permitted.
    * :attr:`max_cert_validity_days` — maximum certificate validity in days (``None`` = no limit).
    * :attr:`max_crl_validity_days` — maximum CRL validity in days (``None`` = no limit).
    * :attr:`allow_ca_issuance` — whether BasicConstraints ca=True is permitted in issued certs.
    * :attr:`allow_auto_gen_pki` — whether auto-generated PKI may be enabled.
    * :attr:`allow_self_signed_ca` — whether self-signed CAs with credentials are allowed.
    * :attr:`require_physical_hsm` — whether key storage must be a physical HSM.
    * :attr:`permitted_no_onboarding_pki_protocols` — JSON list of allowed
      :class:`onboarding.models.NoOnboardingPkiProtocol` integer values.
    * :attr:`permitted_onboarding_protocols` — JSON list of allowed
      :class:`onboarding.models.OnboardingProtocol` integer values.

    Calling :meth:`apply_security_settings` applies the mode defaults onto this instance.
    """

    class SecurityModeChoices(models.TextChoices):
        """Types of security modes."""

        LAB = '0', _('Lab / Development')
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
            'Minimum RSA key size in bits that certificates must meet. '
            'Set to null to disallow RSA entirely.'
        ),
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

    # -- Certificate / CRL validity ---------------------------------------

    max_cert_validity_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=_(
            'Maximum certificate validity period in days. '
            'Set to null for no limit.'
        ),
    )

    max_crl_validity_days = models.PositiveIntegerField(
        null=True,
        blank=True,
        default=None,
        help_text=_(
            'Maximum CRL validity period in days. '
            'Set to null for no limit.'
        ),
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

    # -- Infrastructure constraints ----------------------------------------

    require_physical_hsm = models.BooleanField(
        default=False,
        help_text=_('Require key storage to use a physical HSM (KeyStorageConfig.StorageType.PHYSICAL_HSM).'),
    )

    # -- Protocol allow-lists (stored as JSON lists of integer values) -----

    permitted_no_onboarding_pki_protocols = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of allowed NoOnboardingPkiProtocol integer values '
            '(bitmask flags: CMP_SHARED_SECRET=1, EST_USERNAME_PASSWORD=4, MANUAL=16).'
        ),
    )

    permitted_onboarding_protocols = models.JSONField(
        default=list,
        blank=True,
        help_text=_(
            'JSON list of allowed OnboardingProtocol integer values '
            '(MANUAL=0, CMP_IDEVID=1, CMP_SHARED_SECRET=2, EST_IDEVID=3, '
            'EST_USERNAME_PASSWORD=4, AOKI=5, BRSKI=6, OPC_GDS_PUSH=7).'
        ),
    )

    # ------------------------------------------------------------------
    # Default configurations keyed by mode
    # ------------------------------------------------------------------

    #: All OnboardingProtocol values
    _ALL_ONBOARDING_PROTOCOLS: ClassVar[list[int]] = [0, 1, 2, 3, 4, 5, 6, 7]
    #: All OnboardingProtocol values except MANUAL (0)
    _ONBOARDING_PROTOCOLS_NO_MANUAL: ClassVar[list[int]] = [1, 2, 3, 4, 5, 6, 7]

    _MODE_DEFAULTS: ClassVar[dict[str, _SecurityModeDefaults]] = {
        # ----------------------------------------------------------------
        # Lab / Development
        # ----------------------------------------------------------------
        SecurityModeChoices.LAB: {
            'rsa_minimum_key_size': None,          # all RSA and ECC allowed
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [],
            'max_cert_validity_days': None,        # no limit
            'max_crl_validity_days': None,         # no limit
            'allow_ca_issuance': True,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'require_physical_hsm': False,
            'permitted_no_onboarding_pki_protocols': [1, 4, 16],  # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
            'permitted_onboarding_protocols': _ALL_ONBOARDING_PROTOCOLS,
        },
        # ----------------------------------------------------------------
        # Brownfield Compatible
        # ----------------------------------------------------------------
        SecurityModeChoices.BROWNFIELD: {
            'rsa_minimum_key_size': 1024,
            'not_permitted_ecc_curve_oids': [],
            'not_permitted_signature_algorithm_oids': [],
            'max_cert_validity_days': 1825,        # 5 years
            'max_crl_validity_days': 365,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': True,
            'allow_self_signed_ca': True,
            'require_physical_hsm': False,
            'permitted_no_onboarding_pki_protocols': [1, 4, 16],  # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
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
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
            ],
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 180,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'require_physical_hsm': False,
            'permitted_no_onboarding_pki_protocols': [1, 4, 16],  # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD, MANUAL
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
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
            ],
            'max_cert_validity_days': 365,
            'max_crl_validity_days': 90,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'require_physical_hsm': False,
            'permitted_no_onboarding_pki_protocols': [1, 4],   # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD
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
            'not_permitted_signature_algorithm_oids': [
                HashAlgorithmChoices.MD5,
                HashAlgorithmChoices.SHA1,
                HashAlgorithmChoices.SHA224,
                HashAlgorithmChoices.SHA256,
            ],
            'max_cert_validity_days': 180,
            'max_crl_validity_days': 90,
            'allow_ca_issuance': False,
            'allow_auto_gen_pki': False,
            'allow_self_signed_ca': False,
            'require_physical_hsm': True,
            'permitted_no_onboarding_pki_protocols': [1, 4],   # CMP_SHARED_SECRET, EST_USERNAME_PASSWORD
            'permitted_onboarding_protocols': _ONBOARDING_PROTOCOLS_NO_MANUAL,
        },
    }

    def __str__(self) -> str:
        """Output as string."""
        return f'{self.security_mode}'

    def apply_security_settings(self) -> None:
        """Reset all thresholds to the defaults for the current security mode.

        Reads the defaults from :attr:`_MODE_DEFAULTS` and writes them onto this
        instance, then saves it.

        :raises ValueError: If :attr:`security_mode` is not a recognised mode.
        """
        if not self.security_mode:
            return

        defaults = self._MODE_DEFAULTS.get(self.security_mode)
        if defaults is None:
            msg = f'No defaults defined for security mode: {self.security_mode}'
            raise ValueError(msg)

        self.rsa_minimum_key_size = defaults['rsa_minimum_key_size']
        self.not_permitted_ecc_curve_oids = list(defaults['not_permitted_ecc_curve_oids'])
        self.not_permitted_signature_algorithm_oids = list(defaults['not_permitted_signature_algorithm_oids'])
        self.max_cert_validity_days = defaults['max_cert_validity_days']
        self.max_crl_validity_days = defaults['max_crl_validity_days']
        self.allow_ca_issuance = defaults['allow_ca_issuance']
        self.allow_auto_gen_pki = defaults['allow_auto_gen_pki']
        self.allow_self_signed_ca = defaults['allow_self_signed_ca']
        self.require_physical_hsm = defaults['require_physical_hsm']
        self.permitted_no_onboarding_pki_protocols = list(defaults['permitted_no_onboarding_pki_protocols'])
        self.permitted_onboarding_protocols = list(defaults['permitted_onboarding_protocols'])
        self.save(update_fields=[
            'rsa_minimum_key_size',
            'not_permitted_ecc_curve_oids',
            'not_permitted_signature_algorithm_oids',
            'max_cert_validity_days',
            'max_crl_validity_days',
            'allow_ca_issuance',
            'allow_auto_gen_pki',
            'allow_self_signed_ca',
            'require_physical_hsm',
            'permitted_no_onboarding_pki_protocols',
            'permitted_onboarding_protocols',
        ])

    @classmethod
    def get_settings_preview_json(cls) -> str:
        """Return a JSON string of each mode's display-friendly threshold values for the settings JS.

        :returns: JSON-encoded ``{mode_value: {field: display_value, ...}, ...}``.
        """
        ecc_labels = dict(cls.NamedCurveChoices.choices)
        sig_labels = dict(cls.HashAlgorithmChoices.choices)

        # Build label maps from the actual onboarding enum definitions
        no_onboarding_labels: dict[int, str] = {c.value: str(c.label) for c in NoOnboardingPkiProtocol}
        onboarding_labels: dict[int, str] = {c.value: str(c.label) for c in OnboardingProtocol}

        preview: dict[str, dict[str, object]] = {}
        for mode, defaults in cls._MODE_DEFAULTS.items():
            preview[mode] = {
                'rsa_minimum_key_size': defaults['rsa_minimum_key_size'],
                'not_permitted_ecc_curves': [
                    str(ecc_labels.get(oid, oid)) for oid in defaults['not_permitted_ecc_curve_oids']
                ],
                'not_permitted_signature_algorithms': [
                    str(sig_labels.get(oid, oid)) for oid in defaults['not_permitted_signature_algorithm_oids']
                ],
                'max_cert_validity_days': defaults['max_cert_validity_days'],
                'max_crl_validity_days': defaults['max_crl_validity_days'],
                'allow_ca_issuance': defaults['allow_ca_issuance'],
                'allow_auto_gen_pki': defaults['allow_auto_gen_pki'],
                'allow_self_signed_ca': defaults['allow_self_signed_ca'],
                'require_physical_hsm': defaults['require_physical_hsm'],
                'permitted_no_onboarding_pki_protocols': [
                    no_onboarding_labels.get(v, str(v))
                    for v in defaults['permitted_no_onboarding_pki_protocols']
                ],
                'permitted_onboarding_protocols': [
                    onboarding_labels.get(v, str(v))
                    for v in defaults['permitted_onboarding_protocols']
                ],
            }
        return json.dumps(preview)

    def check_mode_transition(self, target_mode: str) -> list[str]:
        """Check whether the existing data satisfies all requirements of *target_mode*.

        Queries certificates, CAs, devices, and system configuration against the
        defaults for *target_mode* and returns a list of human-readable violation
        strings.  An empty list means the transition is safe.

        This method performs only read operations and does **not** modify any data.

        Args:
            target_mode: A :class:`SecurityModeChoices` value (e.g. ``'2'`` for
                         Industrial Standard).

        Returns:
            A list of violation description strings, one per failing check.
            Empty if the transition is fully compliant.

        Raises:
            ValueError: If *target_mode* is not a recognised mode key.
        """
        defaults = self._MODE_DEFAULTS.get(target_mode)
        if defaults is None:
            msg = f'No defaults defined for security mode: {target_mode}'
            raise ValueError(msg)

        mode_label = str(self.SecurityModeChoices(target_mode).label)
        violations: list[str] = []

        # Lazily imported to avoid circular imports at module load time.
        from devices.models import DeviceModel  # noqa: PLC0415
        from pki.models.ca import CaModel  # noqa: PLC0415

        violations.extend(self._check_hsm(defaults, mode_label))
        violations.extend(self._check_auto_gen_pki(defaults, mode_label))
        violations.extend(self._check_self_signed_cas(defaults, mode_label, CaModel))
        violations.extend(self._check_rsa_key_size(defaults, mode_label, CaModel))
        violations.extend(self._check_ecc_curves(defaults, mode_label, CaModel))
        violations.extend(self._check_signature_algorithms(defaults, mode_label, CaModel))
        violations.extend(self._check_crl_validity(defaults, mode_label, CaModel))
        violations.extend(self._check_no_onboarding_protocols(defaults, mode_label, CaModel, DeviceModel))
        violations.extend(self._check_onboarding_protocols(defaults, mode_label, DeviceModel))
        return violations

    # ------------------------------------------------------------------
    # Private helpers — one method per check group
    # ------------------------------------------------------------------

    def _check_hsm(self, defaults: _SecurityModeDefaults, mode_label: str) -> list[str]:
        """Return violations for the require_physical_hsm constraint."""
        if not defaults['require_physical_hsm']:
            return []
        from management.models.key_storage import KeyStorageConfig  # noqa: PLC0415
        try:
            ks = KeyStorageConfig.get_config()
            if ks.storage_type != KeyStorageConfig.StorageType.PHYSICAL_HSM:
                return [
                    f'Key storage is "{ks.get_storage_type_display()}" but '
                    f'{mode_label} requires a Physical HSM.'
                ]
        except KeyStorageConfig.DoesNotExist:
            return [f'{mode_label} requires a Physical HSM but no key storage configuration exists.']
        return []

    def _check_auto_gen_pki(self, defaults: _SecurityModeDefaults, mode_label: str) -> list[str]:
        """Return a violation if auto-generated PKI is enabled but not permitted in the target mode."""
        if not defaults['allow_auto_gen_pki'] and self.auto_gen_pki:
            return [
                f'Auto-generated PKI is currently enabled but is not permitted in {mode_label}.'
            ]
        return []

    @staticmethod
    def _check_self_signed_cas(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for self-signed issuing CAs when the target mode forbids them."""
        if defaults['allow_self_signed_ca']:
            return []
        names = ca_model.objects.filter(
            credential__certificate__is_self_signed=True
        ).values_list('unique_name', flat=True)
        return [
            f'Issuing CA "{n}" has a self-signed certificate, which is not permitted in {mode_label}.'
            for n in names
        ]

    @staticmethod
    def _check_rsa_key_size(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for CA RSA keys below the minimum (or any RSA if banned)."""
        rsa_oid = PublicKeyAlgorithmOid.RSA.dotted_string
        min_rsa: int | None = defaults['rsa_minimum_key_size']
        if min_rsa is None:
            names = ca_model.objects.filter(
                credential__certificate__spki_algorithm_oid=rsa_oid
            ).values_list('unique_name', flat=True)
            return [
                f'Issuing CA "{n}" uses an RSA key, which is not permitted in {mode_label}.'
                for n in names
            ]
        rows = ca_model.objects.filter(
            credential__certificate__spki_algorithm_oid=rsa_oid,
            credential__certificate__spki_key_size__lt=min_rsa,
        ).values_list('unique_name', 'credential__certificate__spki_key_size')
        return [
            f'Issuing CA "{n}" has an RSA key of {sz} bits, below the minimum of {min_rsa} bits '
            f'required by {mode_label}.'
            for n, sz in rows
        ]

    @staticmethod
    def _check_ecc_curves(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for CA certificates using a blocked ECC curve."""
        blocked: list[str] = defaults['not_permitted_ecc_curve_oids']
        if not blocked:
            return []
        ecc_oid = PublicKeyAlgorithmOid.ECC.dotted_string
        rows = ca_model.objects.filter(
            credential__certificate__spki_algorithm_oid=ecc_oid,
            credential__certificate__spki_ec_curve_oid__in=blocked,
        ).values_list('unique_name', 'credential__certificate__spki_ec_curve_oid')
        curve_labels = dict(SecurityConfig.NamedCurveChoices.choices)
        return [
            f'Issuing CA "{n}" uses ECC curve {curve_labels.get(oid, oid)}, '
            f'which is not permitted in {mode_label}.'
            for n, oid in rows
        ]

    @staticmethod
    def _check_signature_algorithms(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for CA certificates signed with a blocked hash algorithm."""
        blocked_hash_oids: list[str] = defaults['not_permitted_signature_algorithm_oids']
        if not blocked_hash_oids:
            return []
        # Map AlgorithmIdentifier OIDs (stored in CertificateModel) to the hash OIDs
        blocked_sig_oids = [
            alg_id.value.dotted_string
            for alg_id in AlgorithmIdentifier
            if alg_id.hash_algorithm is not None
            and alg_id.hash_algorithm.dotted_string in blocked_hash_oids
        ]
        if not blocked_sig_oids:
            return []
        rows = ca_model.objects.filter(
            credential__certificate__signature_algorithm_oid__in=blocked_sig_oids,
        ).values_list('unique_name', 'credential__certificate__signature_algorithm_oid')
        hash_labels = dict(SecurityConfig.HashAlgorithmChoices.choices)
        violations: list[str] = []
        for ca_name, sig_oid in rows:
            try:
                hash_algo = AlgorithmIdentifier.from_dotted_string(sig_oid).hash_algorithm
                label = hash_labels.get(hash_algo.dotted_string if hash_algo else '', sig_oid)
            except ValueError:
                label = sig_oid
            violations.append(
                f'Issuing CA "{ca_name}" uses signature algorithm with hash {label}, '
                f'which is not permitted in {mode_label}.'
            )
        return violations

    @staticmethod
    def _check_crl_validity(
        defaults: _SecurityModeDefaults, mode_label: str, ca_model: type[CaModel],
    ) -> list[str]:
        """Return violations for CAs whose CRL validity exceeds the target mode maximum."""
        max_days: int | None = defaults['max_crl_validity_days']
        if max_days is None:
            return []
        max_hours = float(max_days) * 24
        rows = ca_model.objects.filter(
            crl_validity_hours__gt=max_hours
        ).values_list('unique_name', 'crl_validity_hours')
        return [
            f'Issuing CA "{n}" has a CRL validity of {h:.2f} hours ({h / 24:.1f} days), '
            f'exceeding the maximum of {max_days} days in {mode_label}.'
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
                no_onboarding_config__isnull=False
            ).values_list('unique_name', 'no_onboarding_config__pki_protocols'):
                if bitmask is not None and (bitmask & proto.value) == proto.value:
                    violations.append(
                        f'Issuing CA "{ca_name}" uses no-onboarding protocol "{label}", '
                        f'which is not permitted in {mode_label}.'
                    )
            for dev_name, bitmask in device_model.objects.filter(
                no_onboarding_config__isnull=False
            ).values_list('common_name', 'no_onboarding_config__pki_protocols'):
                if bitmask is not None and (bitmask & proto.value) == proto.value:
                    violations.append(
                        f'Device "{dev_name}" uses no-onboarding protocol "{label}", '
                        f'which is not permitted in {mode_label}.'
                    )
        return violations

    @staticmethod
    def _check_onboarding_protocols(
        defaults: _SecurityModeDefaults, mode_label: str, device_model: type[DeviceModel],
    ) -> list[str]:
        """Return violations for devices using an onboarding protocol blocked by the target mode."""
        permitted: list[int] = defaults['permitted_onboarding_protocols']
        proto_labels: dict[int, str] = {c.value: str(c.label) for c in OnboardingProtocol}
        rows = device_model.objects.filter(
            onboarding_config__isnull=False
        ).exclude(
            onboarding_config__onboarding_protocol__in=permitted
        ).values_list('common_name', 'onboarding_config__onboarding_protocol')
        return [
            f'Device "{n}" uses onboarding protocol "{proto_labels.get(p, str(p))}", '
            f'which is not permitted in {mode_label}.'
            for n, p in rows
        ]
