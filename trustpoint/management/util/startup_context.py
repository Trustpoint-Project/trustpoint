"""Context builder for startup strategies."""

from __future__ import annotations

from typing import TYPE_CHECKING

from appsecrets.models import AppSecretBackendKind, AppSecretBackendModel
from crypto.runtime import configured_backend_kind
from setup_wizard.tls_credential import load_staged_tls_credential

if TYPE_CHECKING:
    from packaging.version import Version

    from crypto.models import BackendKind
    from management.util.startup_strategies import OutputWriter, StartupContext


class StartupContextBuilder:
    """Builder for creating simplified startup context objects."""

    def __init__(self, output: OutputWriter, current_version: Version) -> None:
        """Initialize the context builder."""
        self.output = output
        self.current_version = current_version
        self.db_version: Version | None = None
        self.backend_kind: BackendKind | None = None
        self.appsecrets_configured = False
        self.has_staged_tls = False

    def with_db_version(self, db_version: Version | None) -> StartupContextBuilder:
        """Set the previously persisted application version."""
        self.db_version = db_version
        return self

    def collect_backend_state(self) -> StartupContextBuilder:
        """Collect the configured managed-crypto backend kind, if any."""
        self.output.write('Checking configured crypto backend...')
        try:
            self.backend_kind = configured_backend_kind()
        except Exception as exc:  # noqa: BLE001
            self.output.write(f'Could not determine crypto backend configuration: {exc}')
            self.backend_kind = None
            return self

        if self.backend_kind is None:
            self.output.write('No active crypto backend profile is configured yet.')
        else:
            self.output.write(f'Configured crypto backend: {self.backend_kind.value}')
        return self

    def collect_appsecret_state(self) -> StartupContextBuilder:
        """Collect whether the app-secret subsystem has a coherent configuration row."""
        self.output.write('Checking application-secret backend configuration...')
        try:
            backend = AppSecretBackendModel.objects.first()
        except Exception as exc:  # noqa: BLE001
            self.output.write(f'Could not inspect app-secret backend configuration: {exc}')
            self.appsecrets_configured = False
            return self

        if backend is None:
            self.output.write('No application-secret backend is configured yet.')
            self.appsecrets_configured = False
            return self

        try:
            if backend.backend_kind == AppSecretBackendKind.PKCS11:
                pkcs11_config = backend.pkcs11_config
                del pkcs11_config
                self.appsecrets_configured = True
            elif backend.backend_kind == AppSecretBackendKind.SOFTWARE:
                software_config = backend.software_config
                del software_config
                self.appsecrets_configured = True
            else:
                self.appsecrets_configured = False
        except Exception:  # noqa: BLE001
            self.appsecrets_configured = False

        self.output.write(f'Application-secret backend configured: {self.appsecrets_configured}')
        return self

    def collect_tls_staging_state(self) -> StartupContextBuilder:
        """Collect whether a staged wizard TLS credential exists for bootstrap mode."""
        self.output.write('Checking for staged bootstrap TLS material...')
        try:
            self.has_staged_tls = load_staged_tls_credential() is not None
        except Exception as exc:  # noqa: BLE001
            self.output.write(f'Could not load staged TLS material: {exc}')
            self.has_staged_tls = False
            return self

        self.output.write(f'Staged TLS credential available: {self.has_staged_tls}')
        return self

    def build(self) -> StartupContext:
        """Build the StartupContext object."""
        from management.util.startup_strategies import StartupContext, WizardState  # noqa: PLC0415

        return StartupContext(
            current_version=self.current_version,
            db_version=self.db_version,
            wizard_state_enum=WizardState.COMPLETED,
            wizard_current_step=None,
            backend_kind=self.backend_kind,
            appsecrets_configured=self.appsecrets_configured,
            has_staged_tls=self.has_staged_tls,
            output=self.output,
        )
