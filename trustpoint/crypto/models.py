"""Django persistence models for crypto provider profiles, managed keys, and capability snapshots."""

from __future__ import annotations

import uuid

from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector
from crypto.domain.algorithms import KeyAlgorithm
from crypto.domain.policies import SigningExecutionMode
from crypto.domain.refs import ManagedKeyRef


class ProbeStatus(models.TextChoices):
    """Persisted provider capability probe status."""

    NEVER = 'never', 'Never probed'
    SUCCESS = 'success', 'Success'
    FAILURE = 'failure', 'Failure'


class ProviderAuthSource(models.TextChoices):
    """How the provider profile resolves the user PIN."""

    ENV = 'env', 'Environment variable'
    FILE = 'file', 'File path'


class ManagedKeyStatus(models.TextChoices):
    """Lifecycle and verification state for a managed key binding."""

    ACTIVE = 'active', 'Active'
    MISSING = 'missing', 'Missing from provider'
    MISMATCH = 'mismatch', 'Public key mismatch'
    ERROR = 'error', 'Verification error'


class CryptoProviderProfileModel(models.Model):
    """Configured PKCS#11 provider profile."""

    name = models.CharField(max_length=100, unique=True)
    module_path = models.TextField()

    token_label = models.CharField(max_length=128, null=True, blank=True)
    token_serial = models.CharField(max_length=128, null=True, blank=True)
    slot_id = models.PositiveIntegerField(null=True, blank=True)

    auth_source = models.CharField(max_length=16, choices=ProviderAuthSource.choices)
    auth_source_ref = models.TextField(
        help_text='Environment variable name or PIN file path depending on auth_source.',
    )

    max_sessions = models.PositiveIntegerField(default=8)
    borrow_timeout_seconds = models.FloatField(default=5.0)
    rw_sessions = models.BooleanField(default=True)

    active = models.BooleanField(default=False)

    last_probe_status = models.CharField(
        max_length=16,
        choices=ProbeStatus.choices,
        default=ProbeStatus.NEVER,
    )
    last_probe_at = models.DateTimeField(null=True, blank=True)
    last_probe_error = models.TextField(null=True, blank=True)

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
        db_table = 'crypto_provider_profile'
        indexes = [
            models.Index(fields=['active']),
            models.Index(fields=['name']),
            models.Index(fields=['token_serial']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['active'],
                condition=models.Q(active=True),
                name='crypto_single_active_provider_profile',
            ),
        ]

    def clean(self) -> None:
        """Validate the provider profile shape."""
        if not self.name.strip():
            raise ValidationError({'name': 'Provider profile name must not be empty.'})
        if not self.module_path.strip():
            raise ValidationError({'module_path': 'PKCS#11 module path must not be empty.'})
        if not self.auth_source_ref.strip():
            raise ValidationError({'auth_source_ref': 'auth_source_ref must not be empty.'})
        if self.max_sessions < 1:
            raise ValidationError({'max_sessions': 'max_sessions must be at least 1.'})
        if self.borrow_timeout_seconds <= 0:
            raise ValidationError({'borrow_timeout_seconds': 'borrow_timeout_seconds must be greater than zero.'})
        if not any((self.token_label, self.token_serial, self.slot_id is not None)):
            raise ValidationError('At least one token selector field must be configured.')

        if self.auth_source not in {ProviderAuthSource.ENV, ProviderAuthSource.FILE}:
            raise ValidationError(
                {'auth_source': f'Unsupported auth source {self.auth_source!r}. Only env and file are allowed.'}
            )

    def build_provider_profile(self) -> Pkcs11ProviderProfile:
        """Convert the Django model into the adapter-level provider profile."""
        selector = Pkcs11TokenSelector(
            token_label=self.token_label or None,
            token_serial=self.token_serial or None,
            slot_id=self.slot_id,
        )

        if self.auth_source == ProviderAuthSource.ENV:
            return Pkcs11ProviderProfile(
                name=self.name,
                module_path=self.module_path,
                token=selector,
                user_pin_env_var=self.auth_source_ref,
                max_sessions=self.max_sessions,
                borrow_timeout_seconds=self.borrow_timeout_seconds,
                rw_sessions=self.rw_sessions,
            )
        if self.auth_source == ProviderAuthSource.FILE:
            return Pkcs11ProviderProfile(
                name=self.name,
                module_path=self.module_path,
                token=selector,
                user_pin_file=self.auth_source_ref,
                max_sessions=self.max_sessions,
                borrow_timeout_seconds=self.borrow_timeout_seconds,
                rw_sessions=self.rw_sessions,
            )
        raise ValidationError(
            {'auth_source': f'Unsupported auth source {self.auth_source!r}. Only env and file are allowed.'}
        )

    def __str__(self) -> str:
        return self.name


class CryptoManagedKeyModel(models.Model):
    """Persistent application-side binding to a PKCS#11-managed key."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    alias = models.CharField(
        max_length=255,
        unique=True,
        help_text='Stable Trustpoint application-facing key alias.',
    )
    provider_profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.PROTECT,
        related_name='managed_keys',
    )

    key_id_hex = models.CharField(
        max_length=128,
        help_text='Hex-encoded PKCS#11 CKA_ID used as the primary provider-side identity.',
    )
    label = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text='Optional human-readable PKCS#11 label.',
    )
    algorithm = models.CharField(max_length=16)
    public_key_fingerprint_sha256 = models.CharField(
        max_length=64,
        help_text='SHA-256 fingerprint of SubjectPublicKeyInfo DER, hex encoded.',
    )
    signing_execution_mode = models.CharField(
        max_length=32,
        default=SigningExecutionMode.COMPLETE_HSM.value,
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
    last_verification_error = models.TextField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'crypto_managed_key'
        indexes = [
            models.Index(fields=['provider_profile', 'status']),
            models.Index(fields=['alias']),
            models.Index(fields=['key_id_hex']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['provider_profile', 'key_id_hex'],
                name='crypto_managed_key_unique_profile_key_id',
            ),
        ]

    def clean(self) -> None:
        """Validate the managed-key record shape."""
        if not self.alias.strip():
            raise ValidationError({'alias': 'Managed key alias must not be empty.'})

        if not self.key_id_hex.strip():
            raise ValidationError({'key_id_hex': 'Managed key CKA_ID hex must not be empty.'})
        try:
            bytes.fromhex(self.key_id_hex)
        except ValueError as exc:
            raise ValidationError({'key_id_hex': 'Managed key CKA_ID must be valid hexadecimal.'}) from exc

        allowed_algorithms = {member.value for member in KeyAlgorithm}
        if self.algorithm not in allowed_algorithms:
            raise ValidationError({'algorithm': f'Unsupported key algorithm {self.algorithm!r}.'})

        allowed_signing_modes = {member.value for member in SigningExecutionMode}
        if self.signing_execution_mode not in allowed_signing_modes:
            raise ValidationError(
                {'signing_execution_mode': f'Unsupported signing execution mode {self.signing_execution_mode!r}.'}
            )

        if len(self.public_key_fingerprint_sha256) != 64:
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

    def __str__(self) -> str:
        return self.alias


class CryptoProviderCapabilitySnapshotModel(models.Model):
    """Append-only history of probed PKCS#11 provider capabilities."""

    profile = models.ForeignKey(
        CryptoProviderProfileModel,
        on_delete=models.CASCADE,
        related_name='capability_snapshots',
    )
    status = models.CharField(max_length=16, choices=ProbeStatus.choices)

    probed_at = models.DateTimeField(default=timezone.now, editable=False)
    probe_hash = models.CharField(max_length=64, db_index=True)

    token_label = models.CharField(max_length=128, null=True, blank=True)
    token_serial = models.CharField(max_length=128, null=True, blank=True)
    token_model = models.CharField(max_length=128, null=True, blank=True)
    token_manufacturer = models.CharField(max_length=128, null=True, blank=True)
    slot_id = models.PositiveIntegerField(null=True, blank=True)

    snapshot = models.JSONField(default=dict)
    error_summary = models.TextField(null=True, blank=True)

    class Meta:
        db_table = 'crypto_provider_capability_snapshot'
        indexes = [
            models.Index(fields=['profile', 'probed_at']),
            models.Index(fields=['profile', 'status']),
            models.Index(fields=['token_serial']),
        ]
        ordering = ['-probed_at', '-id']

    def __str__(self) -> str:
        return f'{self.profile.name} @ {self.probed_at.isoformat()} [{self.status}]'
