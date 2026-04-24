"""Startup strategies for Trustpoint bootstrap and completed runtime startup."""

from __future__ import annotations

import io
import ipaddress
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes
from django.core.management import call_command
from packaging.version import Version
from trustpoint_core.serializer import CertificateCollectionSerializer, CredentialSerializer

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel
from appsecrets.service import DEK_LENGTH_BYTES, AppSecretConfigurationError, get_app_secret_service
from crypto.models import BackendKind
from management.models import AppVersion, NotificationConfig
from management.nginx_paths import NGINX_CERT_CHAIN_PATH, NGINX_CERT_PATH, NGINX_KEY_PATH
from pki.models.truststore import ActiveTrustpointTlsServerCredentialModel
from setup_wizard.models import SetupWizardConfigModel
from setup_wizard.tls_credential import TlsServerCredentialGenerator, load_staged_tls_credential


class OutputWriter(Protocol):
    """Protocol for output writing (stdout/stderr)."""

    def write(self, msg: str) -> None:
        """Write a message to output."""
        ...

    def success(self, msg: str) -> str:
        """Format a success message."""
        ...

    def error(self, msg: str) -> str:
        """Format an error message."""
        ...

    def warning(self, msg: str) -> str:
        """Format a warning message."""
        ...


class WizardState(Enum):
    """Wizard completion state relevant for startup."""

    COMPLETED = 'COMPLETED'
    INCOMPLETE = 'INCOMPLETE'


@dataclass(slots=True)
class StartupContext:
    """Reduced startup context for the new bootstrap/runtime split."""

    current_version: Version
    db_version: Version | None
    wizard_state_enum: WizardState
    wizard_current_step: SetupWizardConfigModel.FreshInstallCurrentStep | None
    backend_kind: BackendKind | None
    appsecrets_configured: bool
    has_staged_tls: bool
    output: OutputWriter

    @property
    def is_wizard_completed(self) -> bool:
        """Return whether the setup wizard has completed."""
        return self.wizard_state_enum == WizardState.COMPLETED


class StartupStrategy(ABC):
    """Abstract base class for startup strategies."""

    @abstractmethod
    def execute(self, context: StartupContext) -> None:
        """Execute the strategy."""

    @abstractmethod
    def get_description(self) -> str:
        """Return a human-readable strategy description."""


class TlsMaterialStrategy(ABC):
    """Strategy for producing nginx TLS PEM files."""

    @abstractmethod
    def apply(self, context: StartupContext) -> None:
        """Write the effective TLS material to the nginx runtime file paths."""

    @staticmethod
    def _write_pem_files(private_key_pem: str, certificate_pem: str, chain_pem: str) -> None:
        """Write PEM files to the nginx runtime locations."""
        NGINX_KEY_PATH.write_text(private_key_pem)
        NGINX_CERT_PATH.write_text(certificate_pem)

        if chain_pem.strip():
            NGINX_CERT_CHAIN_PATH.write_text(chain_pem)
        elif NGINX_CERT_CHAIN_PATH.exists():
            NGINX_CERT_CHAIN_PATH.unlink()

    @staticmethod
    def _render_serializer_pems(credential_serializer: CredentialSerializer) -> tuple[str, str, str]:
        """Render PEM strings from a staged/generated credential serializer."""
        private_key_serializer = credential_serializer.get_private_key_serializer()
        certificate_serializer = credential_serializer.get_certificate_serializer()
        if private_key_serializer is None or certificate_serializer is None:
            msg = 'The TLS credential serializer is missing its private key or certificate.'
            raise RuntimeError(msg)

        chain_certificates = list(credential_serializer.additional_certificates or [])
        chain_pem = ''
        if chain_certificates:
            chain_pem = CertificateCollectionSerializer(chain_certificates).as_pem().decode()

        return (
            private_key_serializer.as_pkcs8_pem().decode(),
            certificate_serializer.as_pem().decode(),
            chain_pem,
        )

    @staticmethod
    def _log_serializer_fingerprint(context: StartupContext, credential_serializer: CredentialSerializer) -> None:
        """Log the SHA-256 fingerprint of a serializer-backed TLS certificate."""
        certificate_serializer = credential_serializer.get_certificate_serializer()
        if certificate_serializer is None:
            msg = 'The TLS credential serializer is missing its certificate.'
            raise RuntimeError(msg)
        fingerprint = certificate_serializer.as_crypto().fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{byte:02X}' for byte in fingerprint)
        context.output.write(f'TLS SHA256 fingerprint: {formatted}')


class BootstrapTlsMaterialStrategy(TlsMaterialStrategy):
    """Bootstrap-mode TLS: use staged wizard files or generate a temporary credential."""

    def apply(self, context: StartupContext) -> None:
        """Write bootstrap TLS files without touching encrypted database state."""
        credential_serializer: CredentialSerializer | None
        try:
            credential_serializer = load_staged_tls_credential()
        except Exception as exc:  # noqa: BLE001
            context.output.write(
                context.output.warning(
                    f'Failed to load staged TLS material for bootstrap mode: {exc}. '
                    'Generating a temporary bootstrap credential instead.'
                )
            )
            credential_serializer = None

        if credential_serializer is not None:
            context.output.write('Using staged TLS credential for bootstrap mode.')
        else:
            context.output.write('Generating temporary bootstrap TLS credential.')
            credential_serializer = TlsServerCredentialGenerator(
                ipv4_addresses=[ipaddress.IPv4Address('127.0.0.1')],
                ipv6_addresses=[ipaddress.IPv6Address('::1')],
                domain_names=['localhost'],
            ).generate_tls_server_credential()

        private_key_pem, certificate_pem, chain_pem = self._render_serializer_pems(credential_serializer)
        self._write_pem_files(private_key_pem, certificate_pem, chain_pem)
        context.output.write(context.output.success('Bootstrap TLS files are ready for nginx.'))
        self._log_serializer_fingerprint(context, credential_serializer)


class ActiveDatabaseTlsMaterialStrategy(TlsMaterialStrategy):
    """Completed-mode TLS: restore the active TLS credential from the database."""

    def apply(self, context: StartupContext) -> None:
        """Restore TLS PEM files from the active TLS credential."""
        context.output.write('Restoring active TLS credential from the database...')

        try:
            active_tls = ActiveTrustpointTlsServerCredentialModel.objects.select_related('credential').get(id=1)
        except ActiveTrustpointTlsServerCredentialModel.DoesNotExist as exc:
            msg = 'The setup wizard is complete, but no active TLS server credential is configured.'
            raise RuntimeError(msg) from exc

        credential_model = active_tls.credential
        if credential_model is None:
            msg = 'The setup wizard is complete, but the active TLS binding has no credential.'
            raise RuntimeError(msg)

        try:
            private_key_pem = credential_model.get_private_key_serializer().as_pkcs8_pem().decode()
            certificate_pem = credential_model.get_certificate_serializer().as_pem().decode()
            chain_pem = credential_model.get_certificate_chain_serializer().as_pem().decode()
        except Exception as exc:  # noqa: BLE001
            msg = f'Failed to restore the active TLS credential from the database: {exc}'
            raise RuntimeError(msg) from exc

        self._write_pem_files(private_key_pem, certificate_pem, chain_pem)
        fingerprint = credential_model.get_certificate().fingerprint(hashes.SHA256())
        formatted = ':'.join(f'{byte:02X}' for byte in fingerprint)
        context.output.write(context.output.success('Active TLS files restored successfully.'))
        context.output.write(f'TLS SHA256 fingerprint: {formatted}')


class RuntimeInitialization:
    """Shared post-branch startup work that is independent of storage backend legacy state."""

    def initialize(self, context: StartupContext) -> None:
        """Perform shared runtime initialization after TLS handling succeeded."""
        context.output.write('Initializing Trustpoint runtime...')
        self._sync_app_version(context)
        self._collect_static_files(context)
        self._compile_messages(context)
        self._initialize_notifications(context)
        context.output.write(context.output.success('Trustpoint initialization complete'))

    @staticmethod
    def _sync_app_version(context: StartupContext) -> None:
        """Persist the running application version after migrations are safe."""
        app_version, _ = AppVersion.objects.get_or_create(pk=1)
        if context.db_version is None:
            context.output.write('No persisted application version found. Creating startup version record.')
        elif context.db_version != context.current_version:
            context.output.write(
                f'Updating application version from {context.db_version} to {context.current_version}.'
            )
        else:
            context.output.write(f'Application version matches the database record: {context.current_version}.')

        try:
            app_version.container_id = Path('/etc/hostname').read_text(encoding='utf-8').strip()
        except FileNotFoundError:
            app_version.container_id = 'unknown'
        app_version.version = str(context.current_version)
        app_version.save()

    @staticmethod
    def _collect_static_files(context: StartupContext) -> None:
        """Collect static files for the current container image."""
        context.output.write('Collecting static files...')
        with io.StringIO() as fake_out:
            call_command('collectstatic', '--noinput', stdout=fake_out)

    @staticmethod
    def _compile_messages(context: StartupContext) -> None:
        """Compile translation messages."""
        context.output.write('Compiling translation messages...')
        with io.StringIO() as fake_out:
            call_command('compilemessages', '-l', 'de', '-l', 'en', stdout=fake_out)

    @staticmethod
    def _initialize_notifications(context: StartupContext) -> None:
        """Ensure notifications are enabled and scheduled."""
        context.output.write('Initializing notifications...')
        try:
            notification_config = NotificationConfig.get()
            if not notification_config.enabled:
                notification_config.enabled = True
                notification_config.save(update_fields=['enabled'])
                context.output.write('Notifications enabled')
            call_command('init_notifications')
            context.output.write('Notification scheduling initialized')
        except Exception as exc:  # noqa: BLE001
            context.output.write(context.output.warning(f'Could not initialize notifications: {exc}'))


class BootstrapStartupStrategy(StartupStrategy):
    """Wizard-incomplete startup: bootstrap mode without encrypted DB secret dependencies."""

    def __init__(
        self,
        tls_strategy: TlsMaterialStrategy | None = None,
        runtime_initialization: RuntimeInitialization | None = None,
    ) -> None:
        self.tls_strategy = tls_strategy or BootstrapTlsMaterialStrategy()
        self.runtime_initialization = runtime_initialization or RuntimeInitialization()

    def execute(self, context: StartupContext) -> None:
        """Enter bootstrap mode and prepare temporary/staged TLS for nginx."""
        context.output.write(self.get_description())
        self._ensure_bootstrap_db_state(context)
        self.tls_strategy.apply(context)
        self.runtime_initialization.initialize(context)

    def get_description(self) -> str:
        """Return the branch description."""
        return 'Bootstrap mode startup (setup wizard incomplete)'

    @staticmethod
    def _ensure_bootstrap_db_state(context: StartupContext) -> None:
        """Ensure the wizard DB singleton exists and points at the bootstrap entry step."""
        config = SetupWizardConfigModel.get_singleton()
        bootstrap_step = SetupWizardConfigModel.FreshInstallCurrentStep.CRYPTO_STORAGE
        if config.fresh_install_current_step != bootstrap_step:
            context.output.write(
                'Setup wizard is incomplete; resetting DB-backed current step to CRYPTO_STORAGE.'
            )
            config.fresh_install_current_step = bootstrap_step
            config.save(update_fields=['fresh_install_current_step'])
        else:
            context.output.write('Bootstrap wizard step is already CRYPTO_STORAGE.')


class CompletedRuntimeStartupStrategy(StartupStrategy):
    """Wizard-complete startup: require appsecrets and restore active TLS from encrypted DB state."""

    def __init__(
        self,
        tls_strategy: TlsMaterialStrategy | None = None,
        runtime_initialization: RuntimeInitialization | None = None,
    ) -> None:
        self.tls_strategy = tls_strategy or ActiveDatabaseTlsMaterialStrategy()
        self.runtime_initialization = runtime_initialization or RuntimeInitialization()

    def execute(self, context: StartupContext) -> None:
        """Require appsecrets readiness, restore active TLS, and then finish startup."""
        context.output.write(self.get_description())
        self._ensure_appsecrets_ready(context)
        self.tls_strategy.apply(context)
        self.runtime_initialization.initialize(context)

    def get_description(self) -> str:
        """Return the branch description."""
        return 'Completed runtime startup (setup wizard completed)'

    @staticmethod
    def _ensure_appsecrets_ready(context: StartupContext) -> None:
        """Require that the application-secret subsystem is configured and usable."""
        context.output.write('Checking application-secret readiness...')
        if context.backend_kind is None:
            msg = 'The setup wizard is complete, but no managed crypto backend profile is configured.'
            raise RuntimeError(msg)
        if not context.appsecrets_configured:
            msg = 'The setup wizard is complete, but the application-secret backend is not configured.'
            raise RuntimeError(msg)

        backend = AppSecretBackendModel.objects.first()
        if backend is None:
            msg = 'The setup wizard is complete, but the application-secret backend row is missing.'
            raise RuntimeError(msg)
        if backend.backend_kind != context.backend_kind.value:
            msg = (
                'The setup wizard is complete, but the managed crypto backend '
                f'({context.backend_kind.value}) and application-secret backend ({backend.backend_kind}) disagree.'
            )
            raise RuntimeError(msg)

        if backend.backend_kind == AppSecretBackendKind.PKCS11:
            wrapped_dek = bytes(backend.pkcs11_config.wrapped_dek or b'')
            if not wrapped_dek:
                msg = 'The setup wizard is complete, but the PKCS#11 app-secret backend has no wrapped DEK.'
                raise RuntimeError(msg)
        elif backend.backend_kind == AppSecretBackendKind.SOFTWARE:
            raw_dek = bytes(backend.software_config.raw_dek or b'')
            if len(raw_dek) != DEK_LENGTH_BYTES:
                msg = 'The setup wizard is complete, but the software app-secret backend has no valid DEK.'
                raise RuntimeError(msg)
        else:
            msg = f'Unsupported application-secret backend kind {backend.backend_kind!r}.'
            raise RuntimeError(msg)

        try:
            get_app_secret_service().require_dek()
        except AppSecretConfigurationError as exc:
            msg = f'The application-secret backend is configured but not usable: {exc}'
            raise RuntimeError(msg) from exc
        except Exception as exc:  # noqa: BLE001
            msg = f'Failed to initialize the application-secret backend: {exc}'
            raise RuntimeError(msg) from exc

        context.output.write(context.output.success('Application-secret backend is ready.'))


class StartupStrategySelector:
    """Selector for the simplified startup branch model."""

    @staticmethod
    def select_startup_strategy(context: StartupContext) -> StartupStrategy:
        """Select bootstrap mode or completed-runtime mode."""
        StartupStrategySelector._log_strategy_selection(context)
        if context.is_wizard_completed:
            return CompletedRuntimeStartupStrategy()
        return BootstrapStartupStrategy()

    @staticmethod
    def _log_strategy_selection(context: StartupContext) -> None:
        """Log the simplified startup state that drives branch selection."""
        context.output.write('=== Determining Startup Branch ===')
        context.output.write(f'Wizard State: {context.wizard_state_enum.value}')
        current_step = context.wizard_current_step.name if context.wizard_current_step is not None else 'unknown'
        context.output.write(f'Wizard Step: {current_step}')
        backend_kind = context.backend_kind.value if context.backend_kind is not None else 'unconfigured'
        context.output.write(f'Configured Backend: {backend_kind}')
        context.output.write(f'App-Secret Backend Configured: {context.appsecrets_configured}')
        context.output.write(f'Staged Bootstrap TLS Available: {context.has_staged_tls}')
