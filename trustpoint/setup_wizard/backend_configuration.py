# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Backend configuration shared by the setup wizard and operational bootstrap."""

from __future__ import annotations

from django.core.exceptions import ValidationError as DjangoValidationError

from appsecrets.models import (
    AppSecretBackendKind,
    AppSecretBackendModel,
    AppSecretPkcs11AuthSource,
    AppSecretPkcs11ConfigModel,
    AppSecretSoftwareConfigModel,
)
from appsecrets.service import clear_app_secret_cache, get_app_secret_service
from crypto.models import (
    BackendKind,
    CryptoProviderProfileModel,
    CryptoProviderSoftwareConfigModel,
    SoftwareKeyEncryptionSource,
)


class BackendConfigurationMixin:
    """Apply the same provider and app-secret configuration in both setup paths."""

    @staticmethod
    def _load_existing_backend_profile(backend_kind: BackendKind) -> CryptoProviderProfileModel | None:
        """Return an existing profile for the given backend kind when one already exists."""
        return CryptoProviderProfileModel.objects.filter(backend_kind=backend_kind).order_by('-active', 'id').first()

    @classmethod
    def _ensure_backend_kind_matches_instance(cls, backend_kind: BackendKind) -> None:
        """Reject mixing backend kinds within one Trustpoint instance."""
        existing_kinds = set(CryptoProviderProfileModel.objects.values_list('backend_kind', flat=True))
        if existing_kinds and backend_kind.value not in existing_kinds:
            configured_backend_kind = min(existing_kinds)
            err_msg = (
                'This Trustpoint instance already contains crypto backend '
                f'configuration for {configured_backend_kind!r}.'
            )
            raise DjangoValidationError(err_msg)

    @classmethod
    def _activate_profile(cls, *, backend_kind: BackendKind, default_name: str) -> CryptoProviderProfileModel:
        """Activate or create the singleton profile for the chosen backend kind."""
        cls._ensure_backend_kind_matches_instance(backend_kind)
        existing_profile = cls._load_existing_backend_profile(backend_kind)
        if existing_profile is not None:
            CryptoProviderProfileModel.objects.filter(active=True).exclude(pk=existing_profile.pk).update(active=False)
            existing_profile.active = True
            existing_profile.save()
            return existing_profile

        CryptoProviderProfileModel.objects.filter(active=True).update(active=False)
        profile = CryptoProviderProfileModel(name=default_name, backend_kind=backend_kind, active=True)
        profile.save()
        return profile

    @classmethod
    def _configure_software_backend(cls) -> None:
        """Configure the software backend for the operational instance."""
        profile = cls._activate_profile(
            backend_kind=BackendKind.SOFTWARE,
            default_name='trustpoint-software-demo-testing-backend',
        )
        defaults = {
            'encryption_source': SoftwareKeyEncryptionSource.DEV_PLAINTEXT,
            'encryption_source_ref': '',
            'allow_exportable_private_keys': False,
        }
        config, created = CryptoProviderSoftwareConfigModel.objects.get_or_create(
            profile=profile,
            defaults=defaults,
        )
        if not created:
            for field_name, value in defaults.items():
                setattr(config, field_name, value)
        config.full_clean()
        config.save()

    @staticmethod
    def _configure_software_app_secret_backend() -> None:
        """Configure the software app-secret backend."""
        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.SOFTWARE
        backend.save()

        AppSecretPkcs11ConfigModel.objects.filter(backend=backend).delete()
        software_config, _ = AppSecretSoftwareConfigModel.objects.get_or_create(backend=backend)
        software_config.full_clean()
        software_config.save()

        clear_app_secret_cache()
        get_app_secret_service().ensure_backend_ready()

    @staticmethod
    def _configure_pkcs11_app_secret_backend() -> None:
        """Configure the PKCS#11-backed app-secret subsystem from the active crypto profile."""
        crypto_profile = CryptoProviderProfileModel.objects.get(active=True, backend_kind=BackendKind.PKCS11)
        crypto_config = crypto_profile.pkcs11_config

        backend = AppSecretBackendModel.get_singleton()
        backend.backend_kind = AppSecretBackendKind.PKCS11
        backend.save()

        AppSecretSoftwareConfigModel.objects.filter(backend=backend).delete()
        secret_config, created = AppSecretPkcs11ConfigModel.objects.get_or_create(
            backend=backend,
            defaults={
                'module_path': crypto_config.module_path,
                'token_label': crypto_config.token_label,
                'token_serial': crypto_config.token_serial,
                'slot_id': crypto_config.slot_id,
                'auth_source': AppSecretPkcs11AuthSource(crypto_config.auth_source),
                'auth_source_ref': crypto_config.auth_source_ref,
            },
        )

        changed_runtime = False
        desired_values = {
            'module_path': crypto_config.module_path,
            'token_label': crypto_config.token_label,
            'token_serial': crypto_config.token_serial,
            'slot_id': crypto_config.slot_id,
            'auth_source': AppSecretPkcs11AuthSource(crypto_config.auth_source),
            'auth_source_ref': crypto_config.auth_source_ref,
        }
        if not created:
            for field_name, value in desired_values.items():
                if getattr(secret_config, field_name) != value:
                    changed_runtime = True
                setattr(secret_config, field_name, value)
            if changed_runtime:
                secret_config.wrapped_dek = None
                secret_config.backup_encrypted_dek = None

        secret_config.full_clean()
        secret_config.save()

        clear_app_secret_cache()
        get_app_secret_service().ensure_backend_ready()

    @staticmethod
    def _map_pkcs11_install_exit_code_to_message(return_code: int) -> str:
        """Map PKCS#11 asset-install script exit codes to user-facing error messages."""
        error_messages = {
            1: 'The PKCS#11 install script did not receive the required staged setup values.',
            2: 'The staged PKCS#11 library is missing or no longer belongs to this wizard session.',
            3: 'The staged PKCS#11 user PIN file is missing or no longer belongs to this wizard session.',
            4: 'Failed to install the PKCS#11 library into the protected HSM area.',
            5: 'Failed to create the protected PKCS#11 user PIN file.',
            6: 'Failed to persist the installed PKCS#11 module path for the instance.',
            7: 'The staged PKCS#11 provider config is missing or no longer belongs to this wizard session.',
            8: 'Failed to install the PKCS#11 provider config into the protected HSM area.',
        }
        return error_messages.get(return_code, 'An unknown error occurred while installing PKCS#11 assets.')
