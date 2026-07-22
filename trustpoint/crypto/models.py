"""Django persistence models for provider profiles, managed keys, and capability snapshots."""

from __future__ import annotations

import uuid
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from crypto.adapters.rest.config import RestProviderProfile
from crypto.adapters.software.config import SoftwareProviderProfile
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import SigningExecutionMode
from crypto.domain.refs import ManagedKeyRef

SHA256_HEX_LENGTH = 64


class BackendKind(models.TextChoices):
    """Supported backend kinds."""

    PKCS11 = 'pkcs11', 'PKCS#11'
    SOFTWARE = 'software', 'Software'
    REST = 'rest', 'REST'


class ProbeStatus(models.TextChoices):
    """Persisted provider capability probe status."""

    NEVER = 'never', 'Never probed'
    SUCCESS = 'success', 'Success'
    FAILURE = 'failure', 'Failure'


class ManagedKeyStatus(models.TextChoices):
    """Lifecycle and verification state for a managed key binding."""

    ACTIVE = 'active', 'Active'
    MISSING = 'missing', 'Missing from provider'
    MISMATCH = 'mismatch', 'Public key mismatch'
    ERROR = 'error', 'Verification error'


class Pkcs11AuthSource(models.TextChoices):
    """How the PKCS#11 config resolves the user PIN."""

    ENV = 'env', 'Environment variable'
    FILE = 'file', 'File path'


class SoftwareKeyEncryptionSource(models.TextChoices):
    """How the software backend resolves its key-encryption secret."""

    ENV = 'env', 'Environment variable'
    FILE = 'file', 'File path'
    DEV_PLAINTEXT = 'dev_plaintext', 'Dev plaintext only'


class RestAuthType(models.TextChoices):
    """How the REST backend authenticates to the remote service."""

    NONE = 'none', 'None'
    BEARER_ENV = 'bearer_env', 'Bearer token from environment'
    API_KEY_ENV = 'api_key_env', 'API key from environment'
    MTLS = 'mtls', 'Mutual TLS'


class CryptoProviderProfileModel(models.Model):
    """Configured backend profile for this Trustpoint instance."""

    name = models.CharField(max_length=100, unique=True)
    backend_kind = models.CharField(max_length=16, choices=BackendKind.choices)
    active = models.BooleanField(default=False)

    last_probe_status = models.CharField(
        max_length=16,
        choices=ProbeStatus.choices,
        default=ProbeStatus.NEVER,
    )
    last_probe_at = models.DateTimeField(null=True, blank=True)
    last_probe_error = models.TextField(blank=True, default='')

    current_capability_snapshot = models.ForeignKey(
        'CryptoProviderCapabilitySnapshotModel',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='+',
    )

    created_at = models.DateTimeField(default=timezone.now, editable=False)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database options for provider profiles."""

        db_table = 'crypto_provider_profile'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['active']),
            models.Index(fields=['backend_kind']),
            models.Index(fields=['name']),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['active'],
                condition=models.Q(active=True),
                name='crypto_single_active_provider_profile',
            ),
        ]

    def __str__(self) -> str:
        """Return the provider profile name."""
        return self.name

    def save(self, *args: Any, **kwargs: Any) -> None:
        """Persist the profile after enforcing single-backend validation."""
        self.full_clean()
        super().save(*args, **kwargs)

    def clean(self) -> None:
        """Validate the generic provider profile shape."""
        if not self.name.strip():
            raise ValidationError({'name': 'Provider profile name must not be empty.'})
        allowed_kinds = {member.value for member in BackendKind}
        if self.backend_kind not in allowed_kinds:
            raise ValidationError({'backend_kind': f'Unsupported backend kind {self.backend_kind!r}.'})

        existing_backend_kinds = set(
            CryptoProviderProfileModel.objects.exclude(pk=self.pk).values_list('backend_kind', flat=True)
        )
        if existing_backend_kinds and self.backend_kind not in existing_backend_kinds:
            configured_backend_kind = sorted(existing_backend_kinds)[0]
            raise ValidationError(
                {
                    'backend_kind': (
                        'Trustpoint instances cannot mix crypto backend kinds. '
                        f'This instance is already configured for {configured_backend_kind!r}.'
                    )
                }
            )


class CryptoProviderPkcs11ConfigModel(models.Model):
    """PKCS#11-specific provider configuration."""

    profile = models.OneToOneField(
        CryptoProviderProfileModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='pkcs11_config',
    )

    module_path = models.TextField()
    provider_config_env_var = models.CharField(max_length=128, blank=True, default='')
    provider_config_path = models.TextField(blank=True, default='')
    token_label = models.CharField(max_length=128, blank=True, default='')
    token_serial = models.CharField(max_length=128, blank=True, default='')
    slot_id = models.PositiveIntegerField(null=True, blank=True)

    auth_source = models.CharField(max_length=16, choices=Pkcs11AuthSource.choices)
    auth_source_ref = models.TextField(
        help_text='Environment variable name or PIN file path depending on auth_source.',
    )

    max_sessions = models.PositiveIntegerField(default=8)
    borrow_timeout_seconds = models.FloatField(default=5.0)
    rw_sessions = models.BooleanField(default=True)

    class Meta:
        """Database options for PKCS#11 provider configs."""

        db_table = 'crypto_provider_pkcs11_config'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['token_serial']),
            models.Index(fields=['token_label']),
        ]

    def __str__(self) -> str:
        """Return a readable PKCS#11 provider config label."""
        return f'{self.profile.name} PKCS#11 config'

    def clean(self) -> None:
        """Validate the PKCS#11 config shape."""
        if self.profile.backend_kind != BackendKind.PKCS11:
            raise ValidationError({'profile': 'PKCS#11 config requires a pkcs11 backend profile.'})
        if not self.module_path.strip():
            raise ValidationError({'module_path': 'PKCS#11 module path must not be empty.'})
        if not self.auth_source_ref.strip():
            raise ValidationError({'auth_source_ref': 'auth_source_ref must not be empty.'})
        if self.max_sessions < 1:
            raise ValidationError({'max_sessions': 'max_sessions must be at least 1.'})
        if self.borrow_timeout_seconds <= 0:
            raise ValidationError({'borrow_timeout_seconds': 'borrow_timeout_seconds must be greater than zero.'})
        if not any((self.token_label, self.token_serial, self.slot_id is not None)):
            msg = 'At least one token selector field must be configured.'
            raise ValidationError(msg)

    def build_provider_profile(self) -> Pkcs11ProviderProfile:
        """Convert the Django model into the adapter-level PKCS#11 provider profile."""
        selector = Pkcs11TokenSelector(
            token_label=self.token_label or None,
            token_serial=self.token_serial or None,
            slot_id=self.slot_id,
        )

        if self.auth_source == Pkcs11AuthSource.ENV:
            return Pkcs11ProviderProfile(
                name=self.profile.name,
                module_path=self.module_path,
                token=selector,
                user_pin_env_var=self.auth_source_ref,
                max_sessions=self.max_sessions,
                borrow_timeout_seconds=self.borrow_timeout_seconds,
                rw_sessions=self.rw_sessions,
            )

        if self.auth_source == Pkcs11AuthSource.FILE:
            return Pkcs11ProviderProfile(
                name=self.profile.name,
                module_path=self.module_path,
                token=selector,
                user_pin_file=self.auth_source_ref,
                max_sessions=self.max_sessions,
                borrow_timeout_seconds=self.borrow_timeout_seconds,
                rw_sessions=self.rw_sessions,
            )

        raise ValidationError({'auth_source': f'Unsupported PKCS#11 auth source {self.auth_source!r}.'})


class CryptoProviderSoftwareConfigModel(models.Model):
    """Software-backend-specific provider configuration."""

    profile = models.OneToOneField(
        CryptoProviderProfileModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='software_config',
    )

    encryption_source = models.CharField(
        max_length=24,
        choices=SoftwareKeyEncryptionSource.choices,
        default=SoftwareKeyEncryptionSource.ENV,
    )
    encryption_source_ref = models.TextField(
        blank=True,
        default='',
        help_text='Environment variable name or file path containing the encryption secret.',
    )
    allow_exportable_private_keys = models.BooleanField(default=False)

    class Meta:
        """Database options for software provider configs."""

        db_table = 'crypto_provider_software_config'

    def __str__(self) -> str:
        """Return a readable software provider config label."""
        return f'{self.profile.name} software config'

    def clean(self) -> None:
        """Validate the software backend config shape."""
        if self.profile.backend_kind != BackendKind.SOFTWARE:
            raise ValidationError({'profile': 'Software config requires a software backend profile.'})
        if self.encryption_source in {
            SoftwareKeyEncryptionSource.ENV,
            SoftwareKeyEncryptionSource.FILE,
        } and not self.encryption_source_ref.strip():
            raise ValidationError(
                {'encryption_source_ref': 'encryption_source_ref is required for env and file encryption sources.'}
            )

    def build_provider_profile(self) -> SoftwareProviderProfile:
        """Convert the Django model into the adapter-level software provider profile."""
        return SoftwareProviderProfile(
            name=self.profile.name,
            encryption_source=self.encryption_source,
            encryption_source_ref=(self.encryption_source_ref or None),
            allow_exportable_private_keys=self.allow_exportable_private_keys,
        )


class CryptoProviderRestConfigModel(models.Model):
    """REST-backend-specific provider configuration."""

    profile = models.OneToOneField(
        CryptoProviderProfileModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='rest_config',
    )

    base_url = models.URLField()
    auth_type = models.CharField(max_length=24, choices=RestAuthType.choices)
    auth_ref = models.TextField(blank=True, default='')
    timeout_seconds = models.FloatField(default=5.0)
    verify_tls = models.BooleanField(default=True)

    class Meta:
        """Database options for REST provider configs."""

        db_table = 'crypto_provider_rest_config'

    def __str__(self) -> str:
        """Return a readable REST provider config label."""
        return f'{self.profile.name} REST config'

    def clean(self) -> None:
        """Validate the REST backend config shape."""
        if self.profile.backend_kind != BackendKind.REST:
            raise ValidationError({'profile': 'REST config requires a rest backend profile.'})
        if self.timeout_seconds <= 0:
            raise ValidationError({'timeout_seconds': 'timeout_seconds must be greater than zero.'})

        if (
            self.auth_type in {RestAuthType.BEARER_ENV, RestAuthType.API_KEY_ENV, RestAuthType.MTLS}
            and not self.auth_ref.strip()
        ):
            raise ValidationError({'auth_ref': 'auth_ref is required for the selected auth_type.'})

    def build_provider_profile(self) -> RestProviderProfile:
        """Convert the Django model into the adapter-level REST provider profile."""
        return RestProviderProfile(
            name=self.profile.name,
            base_url=self.base_url,
            auth_type=self.auth_type,
            auth_ref=(self.auth_ref or None),
            timeout_seconds=self.timeout_seconds,
            verify_tls=self.verify_tls,
        )


class CryptoManagedKeyModel(models.Model):
    """Persistent application-side binding to a backend-managed key."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    alias = models.CharField(
        max_length=255,
        unique=True,
        help_text='Stable application-unique key alias.',
    )
    provider_label = models.CharField(
        max_length=255,
        blank=True,
        default='',
        help_text='Optional provider-side diagnostic label.',
    )

    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='managed_keys',
    )

    algorithm = models.CharField(max_length=16)
    public_key_fingerprint_sha256 = models.CharField(
        max_length=SHA256_HEX_LENGTH,
        help_text='SHA-256 fingerprint of SubjectPublicKeyInfo DER, hex encoded.',
    )
    signing_execution_mode = models.CharField(
        max_length=32,
        default=SigningExecutionMode.COMPLETE_BACKEND.value,
        help_text='How Trustpoint is allowed to execute managed-key signing.',
    )

    policy_snapshot = models.JSONField(
        default=dict,
        help_text='Persisted summary of the key policy at creation time.',
    )

    status = models.CharField(
        max_length=16,
        choices=ManagedKeyStatus.choices,
        default=ManagedKeyStatus.ACTIVE,
    )
    created_at = models.DateTimeField(default=timezone.now, editable=False)
    last_verified_at = models.DateTimeField(null=True, blank=True)
    last_verification_error = models.TextField(blank=True, default='')
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        """Database options for managed keys."""

        db_table = 'crypto_managed_key'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['provider_profile', 'status']),
            models.Index(fields=['alias']),
        ]

    def __str__(self) -> str:
        """Return the managed-key alias."""
        return self.alias

    def clean(self) -> None:
        """Validate the managed-key record shape."""
        if not self.alias.strip():
            raise ValidationError({'alias': 'Managed key alias must not be empty.'})

        allowed_algorithms = {member.value for member in KeyAlgorithm}
        if self.algorithm not in allowed_algorithms:
            raise ValidationError({'algorithm': f'Unsupported key algorithm {self.algorithm!r}.'})

        allowed_signing_modes = {member.value for member in SigningExecutionMode}
        if self.signing_execution_mode not in allowed_signing_modes:
            raise ValidationError(
                {'signing_execution_mode': f'Unsupported signing execution mode {self.signing_execution_mode!r}.'}
            )

        if len(self.public_key_fingerprint_sha256) != SHA256_HEX_LENGTH:
            raise ValidationError(
                {'public_key_fingerprint_sha256': 'Public-key SHA-256 fingerprint must be 64 hex characters.'}
            )
        try:
            bytes.fromhex(self.public_key_fingerprint_sha256)
        except ValueError as exc:
            raise ValidationError(
                {'public_key_fingerprint_sha256': 'Public-key SHA-256 fingerprint must be valid hexadecimal.'}
            ) from exc

    def to_managed_key_ref(self) -> ManagedKeyRef:
        """Convert the persisted model back into an application-facing managed-key ref."""
        return ManagedKeyRef(
            id=self.id,
            alias=self.alias,
            algorithm=KeyAlgorithm(self.algorithm),
            public_key_fingerprint_sha256=self.public_key_fingerprint_sha256,
            signing_execution_mode=SigningExecutionMode(self.signing_execution_mode),
        )


class CryptoManagedKeyPkcs11BindingModel(models.Model):
    """Provider-specific PKCS#11 binding for a managed key."""

    managed_key = models.OneToOneField(
        CryptoManagedKeyModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='pkcs11_binding',
    )
    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='pkcs11_key_bindings',
    )
    key_id_hex = models.CharField(
        max_length=128,
        help_text='Hex-encoded PKCS#11 CKA_ID used as the primary provider-side identity.',
    )

    class Meta:
        """Database options for PKCS#11 managed-key bindings."""

        db_table = 'crypto_managed_key_pkcs11_binding'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['provider_profile', 'key_id_hex']),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['provider_profile', 'key_id_hex'],
                name='crypto_pkcs11_binding_unique_profile_key_id',
            ),
        ]

    def __str__(self) -> str:
        """Return a readable PKCS#11 managed-key binding label."""
        return f'{self.managed_key.alias} PKCS#11 binding'

    def clean(self) -> None:
        """Validate the PKCS#11 binding shape."""
        if self.provider_profile.backend_kind != BackendKind.PKCS11:
            raise ValidationError({'provider_profile': 'PKCS#11 binding requires a pkcs11 provider profile.'})
        if self.managed_key.provider_profile_id != self.provider_profile_id:
            raise ValidationError(
                {'provider_profile': 'Binding provider_profile must match managed_key.provider_profile.'}
            )
        if not self.key_id_hex.strip():
            raise ValidationError({'key_id_hex': 'Managed key CKA_ID hex must not be empty.'})
        try:
            bytes.fromhex(self.key_id_hex)
        except ValueError as exc:
            raise ValidationError({'key_id_hex': 'Managed key CKA_ID must be valid hexadecimal.'}) from exc


class CryptoManagedKeySoftwareBindingModel(models.Model):
    """Provider-specific software binding for a managed key."""

    managed_key = models.OneToOneField(
        CryptoManagedKeyModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='software_binding',
    )
    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='software_key_bindings',
    )
    key_handle = models.CharField(max_length=128)
    encrypted_private_key_pkcs8_der = models.BinaryField()
    encryption_metadata = models.JSONField(default=dict)

    class Meta:
        """Database options for software managed-key bindings."""

        db_table = 'crypto_managed_key_software_binding'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['provider_profile', 'key_handle']),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['provider_profile', 'key_handle'],
                name='crypto_software_binding_unique_profile_key_handle',
            ),
        ]

    def __str__(self) -> str:
        """Return a readable software managed-key binding label."""
        return f'{self.managed_key.alias} software binding'

    def clean(self) -> None:
        """Validate the software binding shape."""
        if self.provider_profile.backend_kind != BackendKind.SOFTWARE:
            raise ValidationError({'provider_profile': 'Software binding requires a software provider profile.'})
        if self.managed_key.provider_profile_id != self.provider_profile_id:
            raise ValidationError(
                {'provider_profile': 'Binding provider_profile must match managed_key.provider_profile.'}
            )
        if not self.key_handle.strip():
            raise ValidationError({'key_handle': 'Software key_handle must not be empty.'})
        if not self.encrypted_private_key_pkcs8_der:
            raise ValidationError(
                {'encrypted_private_key_pkcs8_der': 'Software binding must contain encrypted private key material.'}
            )


class CryptoManagedKeyProtectedImportBindingModel(models.Model):
    """Encrypted DB binding for imported private keys protected by app-secret encryption."""

    managed_key = models.OneToOneField(
        CryptoManagedKeyModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='protected_import_binding',
    )
    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='protected_import_key_bindings',
    )
    key_handle = models.CharField(max_length=128)
    encrypted_private_key_pkcs8_der_b64 = models.TextField()
    encryption_metadata = models.JSONField(default=dict)

    class Meta:
        """Database options for protected imported managed-key bindings."""

        db_table = 'crypto_managed_key_protected_import_binding'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['provider_profile', 'key_handle']),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['provider_profile', 'key_handle'],
                name='crypto_protected_import_unique_profile_key_handle',
            ),
        ]

    def __str__(self) -> str:
        """Return a readable protected imported-key binding label."""
        return f'{self.managed_key.alias} protected imported-key binding'

    def clean(self) -> None:
        """Validate the protected imported-key binding shape."""
        if self.provider_profile.backend_kind not in {BackendKind.PKCS11, BackendKind.SOFTWARE}:
            raise ValidationError(
                {'provider_profile': 'Protected imported keys require a software or PKCS#11 provider profile.'}
            )
        if self.managed_key.provider_profile_id != self.provider_profile_id:
            raise ValidationError(
                {'provider_profile': 'Binding provider_profile must match managed_key.provider_profile.'}
            )
        if not self.key_handle.strip():
            raise ValidationError({'key_handle': 'Protected imported key_handle must not be empty.'})
        if not self.encrypted_private_key_pkcs8_der_b64:
            raise ValidationError(
                {'encrypted_private_key_pkcs8_der_b64': 'Protected imported key material must not be empty.'}
            )


class CryptoManagedKeyRestBindingModel(models.Model):
    """Provider-specific REST binding for a managed key."""

    managed_key = models.OneToOneField(
        CryptoManagedKeyModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='rest_binding',
    )
    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='rest_key_bindings',
    )
    remote_key_id = models.CharField(max_length=255)
    remote_key_version = models.CharField(max_length=128, blank=True, default='')

    class Meta:
        """Database options for REST managed-key bindings."""

        db_table = 'crypto_managed_key_rest_binding'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['provider_profile', 'remote_key_id']),
        ]
        constraints: ClassVar[list[models.BaseConstraint]] = [
            models.UniqueConstraint(
                fields=['provider_profile', 'remote_key_id', 'remote_key_version'],
                name='crypto_rest_binding_unique_remote_key',
            ),
        ]

    def __str__(self) -> str:
        """Return a readable REST managed-key binding label."""
        return f'{self.managed_key.alias} REST binding'

    def clean(self) -> None:
        """Validate the REST binding shape."""
        if self.provider_profile.backend_kind != BackendKind.REST:
            raise ValidationError({'provider_profile': 'REST binding requires a rest provider profile.'})
        if self.managed_key.provider_profile_id != self.provider_profile_id:
            raise ValidationError(
                {'provider_profile': 'Binding provider_profile must match managed_key.provider_profile.'}
            )
        if not self.remote_key_id.strip():
            raise ValidationError({'remote_key_id': 'REST remote_key_id must not be empty.'})


class CryptoProviderCapabilitySnapshotModel(models.Model):
    """Append-only history of probed provider capabilities."""

    profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.CASCADE,
        related_name='capability_snapshots',
    )
    status = models.CharField(max_length=16, choices=ProbeStatus.choices)
    probed_at = models.DateTimeField(default=timezone.now, editable=False)
    probe_hash = models.CharField(max_length=SHA256_HEX_LENGTH, db_index=True)
    error_summary = models.TextField(blank=True, default='')

    class Meta:
        """Database options for capability snapshots."""

        db_table = 'crypto_provider_capability_snapshot'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['profile', 'probed_at']),
            models.Index(fields=['profile', 'status']),
        ]
        ordering: ClassVar[list[str]] = ['-probed_at', '-id']

    def __str__(self) -> str:
        """Return a readable capability snapshot label."""
        return f'{self.profile.name} @ {self.probed_at.isoformat()} [{self.status}]'


class CryptoProviderCapabilityPkcs11DetailModel(models.Model):
    """PKCS#11-specific capability snapshot detail."""

    snapshot = models.OneToOneField(
        CryptoProviderCapabilitySnapshotModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='pkcs11_detail',
    )
    token_label = models.CharField(max_length=128, blank=True, default='')
    token_serial = models.CharField(max_length=128, blank=True, default='')
    token_model = models.CharField(max_length=128, blank=True, default='')
    token_manufacturer = models.CharField(max_length=128, blank=True, default='')
    slot_id = models.PositiveIntegerField(null=True, blank=True)
    snapshot_payload = models.JSONField(default=dict)

    class Meta:
        """Database options for PKCS#11 capability details."""

        db_table = 'crypto_provider_capability_pkcs11_detail'
        indexes: ClassVar[list[models.Index]] = [
            models.Index(fields=['token_serial']),
        ]

    def __str__(self) -> str:
        """Return a readable PKCS#11 capability detail label."""
        return f'{self.snapshot} PKCS#11 detail'

    def clean(self) -> None:
        """Validate the PKCS#11 detail shape."""
        if self.snapshot.profile.backend_kind != BackendKind.PKCS11:
            raise ValidationError({'snapshot': 'PKCS#11 capability detail requires a pkcs11 provider profile.'})


class CryptoProviderCapabilitySoftwareDetailModel(models.Model):
    """Software-backend-specific capability snapshot detail."""

    snapshot = models.OneToOneField(
        CryptoProviderCapabilitySnapshotModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='software_detail',
    )
    snapshot_payload = models.JSONField(default=dict)

    class Meta:
        """Database options for software capability details."""

        db_table = 'crypto_provider_capability_software_detail'

    def __str__(self) -> str:
        """Return a readable software capability detail label."""
        return f'{self.snapshot} software detail'

    def clean(self) -> None:
        """Validate the software capability detail shape."""
        if self.snapshot.profile.backend_kind != BackendKind.SOFTWARE:
            raise ValidationError({'snapshot': 'Software capability detail requires a software provider profile.'})


class CryptoProviderCapabilityRestDetailModel(models.Model):
    """REST-backend-specific capability snapshot detail."""

    snapshot = models.OneToOneField(
        CryptoProviderCapabilitySnapshotModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='rest_detail',
    )
    snapshot_payload = models.JSONField(default=dict)

    class Meta:
        """Database options for REST capability details."""

        db_table = 'crypto_provider_capability_rest_detail'

    def __str__(self) -> str:
        """Return a readable REST capability detail label."""
        return f'{self.snapshot} REST detail'

    def clean(self) -> None:
        """Validate the REST capability detail shape."""
        if self.snapshot.profile.backend_kind != BackendKind.REST:
            raise ValidationError({'snapshot': 'REST capability detail requires a rest provider profile.'})
