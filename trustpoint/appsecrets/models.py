"""Persistence models for the application-secret encryption subsystem."""

from __future__ import annotations

from typing import ClassVar, Final

from django.core.exceptions import ValidationError
from django.db import models

from crypto.adapters.pkcs11.config import Pkcs11ProviderProfile, Pkcs11TokenSelector


class AppSecretBackendKind(models.TextChoices):
    """Supported app-secret backend kinds."""

    PKCS11 = 'pkcs11', 'PKCS#11'
    SOFTWARE = 'software', 'Software'


class AppSecretPkcs11AuthSource(models.TextChoices):
    """How the app-secret PKCS#11 backend resolves the user PIN."""

    FILE = 'file', 'PIN file'
    ENV = 'env', 'Environment variable'


class AppSecretBackendModel(models.Model):
    """Singleton configuration row for the active application-secret backend."""

    SINGLETON_ID: ClassVar[Final[int]] = 1

    singleton_id = models.PositiveSmallIntegerField(
        primary_key=True,
        default=SINGLETON_ID,
        editable=False,
        help_text='Singleton primary key. Always 1.',
    )
    backend_kind = models.CharField(max_length=16, choices=AppSecretBackendKind.choices)

    class Meta:
        db_table = 'app_secret_backend'

    @classmethod
    def get_singleton(cls) -> AppSecretBackendModel:
        """Return the singleton row, creating an empty one if needed."""
        return cls.objects.get_or_create(
            singleton_id=cls.SINGLETON_ID,
            defaults={'backend_kind': AppSecretBackendKind.SOFTWARE},
        )[0]

    def clean(self) -> None:
        """Validate the configured backend kind."""
        allowed_kinds = {member.value for member in AppSecretBackendKind}
        if self.backend_kind not in allowed_kinds:
            raise ValidationError({'backend_kind': f'Unsupported app-secret backend kind {self.backend_kind!r}.'})

    def save(self, *args: object, **kwargs: object) -> None:
        """Persist after validation while keeping singleton semantics."""
        self.full_clean()
        self.singleton_id = self.SINGLETON_ID
        super().save(*args, **kwargs)


class AppSecretPkcs11ConfigModel(models.Model):
    """PKCS#11 configuration for the application-secret backend."""

    DEFAULT_KEK_LABEL = 'trustpoint-app-secret-kek'

    backend = models.OneToOneField(
        AppSecretBackendModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='pkcs11_config',
    )

    module_path = models.TextField()
    token_label = models.CharField(max_length=128, null=True, blank=True)
    token_serial = models.CharField(max_length=128, null=True, blank=True)
    slot_id = models.PositiveIntegerField(null=True, blank=True)

    auth_source = models.CharField(max_length=16, choices=AppSecretPkcs11AuthSource.choices)
    auth_source_ref = models.TextField(
        help_text='Environment variable name or PIN file path depending on auth_source.',
    )

    kek_label = models.CharField(max_length=128, default=DEFAULT_KEK_LABEL)
    wrapped_dek = models.BinaryField(
        blank=True,
        null=True,
        help_text='DEK wrapped by the HSM KEK.',
    )
    backup_encrypted_dek = models.BinaryField(
        blank=True,
        null=True,
        help_text='Reserved for password-based DEK backup protection.',
    )

    class Meta:
        db_table = 'app_secret_pkcs11_config'

    def clean(self) -> None:
        """Validate the PKCS#11 app-secret configuration."""
        if self.backend.backend_kind != AppSecretBackendKind.PKCS11:
            raise ValidationError({'backend': 'PKCS#11 config requires the pkcs11 app-secret backend.'})
        if not self.module_path.strip():
            raise ValidationError({'module_path': 'PKCS#11 module path must not be empty.'})
        if not self.auth_source_ref.strip():
            raise ValidationError({'auth_source_ref': 'auth_source_ref must not be empty.'})
        if not any((self.token_label, self.token_serial, self.slot_id is not None)):
            raise ValidationError('At least one token selector field must be configured.')
        if not self.kek_label.strip():
            raise ValidationError({'kek_label': 'kek_label must not be empty.'})

    def build_provider_profile(self) -> Pkcs11ProviderProfile:
        """Build a PKCS#11 provider profile for runtime authentication and token selection."""
        selector = Pkcs11TokenSelector(
            token_label=self.token_label or None,
            token_serial=self.token_serial or None,
            slot_id=self.slot_id,
        )

        if self.auth_source == AppSecretPkcs11AuthSource.ENV:
            return Pkcs11ProviderProfile(
                name='trustpoint-app-secrets',
                module_path=self.module_path,
                token=selector,
                user_pin_env_var=self.auth_source_ref,
            )

        if self.auth_source == AppSecretPkcs11AuthSource.FILE:
            return Pkcs11ProviderProfile(
                name='trustpoint-app-secrets',
                module_path=self.module_path,
                token=selector,
                user_pin_file=self.auth_source_ref,
            )

        raise ValidationError({'auth_source': f'Unsupported PKCS#11 auth source {self.auth_source!r}.'})


class AppSecretSoftwareConfigModel(models.Model):
    """Development-only software config for application secrets."""

    backend = models.OneToOneField(
        AppSecretBackendModel,
        primary_key=True,
        on_delete=models.CASCADE,
        related_name='software_config',
    )
    raw_dek = models.BinaryField(
        blank=True,
        null=True,
        help_text='Development-only DEK storage.',
    )

    class Meta:
        db_table = 'app_secret_software_config'

    def clean(self) -> None:
        """Validate the software app-secret configuration."""
        if self.backend.backend_kind != AppSecretBackendKind.SOFTWARE:
            raise ValidationError({'backend': 'Software config requires the software app-secret backend.'})

