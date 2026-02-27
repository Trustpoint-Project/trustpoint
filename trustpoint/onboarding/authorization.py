"""Protocol authorization for the onboarding app."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Protocol

from onboarding.enums import NoOnboardingPkiProtocol, OnboardingProtocol
from trustpoint.logger import LoggerMixin

if TYPE_CHECKING:
    from management.models import SecurityConfig
    from onboarding.models import NoOnboardingConfigModel, OnboardingConfigModel

class HasOnboardingConfig(Protocol):
    """Structural type for any model that carries onboarding / no-onboarding config FKs."""

    onboarding_config: OnboardingConfigModel | None
    no_onboarding_config: NoOnboardingConfigModel | None



class ProtocolCheckStrategy(ABC):
    """Abstract strategy for validating a protocol value against a SecurityConfig allow-list."""

    @abstractmethod
    def check(self, subject: HasOnboardingConfig, cfg: SecurityConfig) -> None:
        """Execute the protocol check.

        Args:
            subject: Any model instance that carries ``onboarding_config`` and
                     ``no_onboarding_config`` attributes (e.g. a device or an issuing CA).
            cfg: The active :class:`~management.models.SecurityConfig` policy object.

        Raises:
            ValueError: If the protocol used by *subject* is not permitted by *cfg*.
        """

class _OnboardingProtocolStrategy(ProtocolCheckStrategy, LoggerMixin):
    """Validates the subject's onboarding protocol against ``SecurityConfig.permitted_onboarding_protocols``."""

    def check(self, subject: HasOnboardingConfig, cfg: SecurityConfig) -> None:
        """Check the onboarding protocol against the permitted list."""
        onboarding_config: OnboardingConfigModel | None = getattr(subject, 'onboarding_config', None)
        if onboarding_config is None:
            self.logger.debug(
                '_OnboardingProtocolStrategy: %s has no onboarding_config; skipping.',
                subject,
            )
            return

        protocol_value: int = onboarding_config.onboarding_protocol
        permitted: list[int] = cfg.permitted_onboarding_protocols or []

        if not permitted:
            msg = (
                'All onboarding protocols are blocked by the active security policy '
                '(permitted_onboarding_protocols is empty).'
            )
            self.logger.warning('OnboardingProtocolAuthorization: %s', msg)
            raise ValueError(msg)

        if protocol_value not in permitted:
            protocol_label = str(OnboardingProtocol(protocol_value).label)
            allowed_labels = [str(OnboardingProtocol(v).label) for v in permitted if v in OnboardingProtocol.values]
            msg = (
                f"Onboarding protocol '{protocol_label}' is not permitted by the active security policy. "
                f"Allowed: {', '.join(allowed_labels)}."
            )
            self.logger.warning('OnboardingProtocolAuthorization: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            'OnboardingProtocolAuthorization: protocol %s is permitted.',
            OnboardingProtocol(protocol_value).label,
        )


class _NoOnboardingPkiProtocolStrategy(ProtocolCheckStrategy, LoggerMixin):
    """Validates every active no-onboarding PKI protocol against the security config allow-list."""

    def check(self, subject: HasOnboardingConfig, cfg: SecurityConfig) -> None:
        """Check every active no-onboarding PKI protocol against the permitted list."""
        no_onboarding_config: NoOnboardingConfigModel | None = getattr(subject, 'no_onboarding_config', None)
        if no_onboarding_config is None:
            self.logger.debug(
                '_NoOnboardingPkiProtocolStrategy: %s has no no_onboarding_config; skipping.',
                subject,
            )
            return

        active_protocols: list[NoOnboardingPkiProtocol] = no_onboarding_config.get_pki_protocols()
        permitted: list[int] = cfg.permitted_no_onboarding_pki_protocols or []

        denied: list[str] = [str(proto.label) for proto in active_protocols if proto.value not in permitted]

        if denied:
            allowed_labels = [
                str(NoOnboardingPkiProtocol(v).label)
                for v in permitted
                if v in NoOnboardingPkiProtocol.values
            ]
            msg = (
                f"No-onboarding PKI protocol(s) {', '.join(denied)} are not permitted "
                f"by the active security policy. "
                f"Allowed: {', '.join(allowed_labels) if allowed_labels else 'none'}."
            )
            self.logger.warning('NoOnboardingPkiProtocolAuthorization: %s', msg)
            raise ValueError(msg)

        self.logger.debug(
            'NoOnboardingPkiProtocolAuthorization: all active protocols permitted (%s).',
            ', '.join(str(p.label) for p in active_protocols) if active_protocols else 'none',
        )

class OnboardingProtocolAuthorization(LoggerMixin):
    """Checks that the subject's onboarding protocol is permitted by the active security config."""

    def __init__(self, strategy: ProtocolCheckStrategy | None = None) -> None:
        """Initialize with an optional custom strategy."""
        self._strategy: ProtocolCheckStrategy = strategy or _OnboardingProtocolStrategy()

    def check(self, subject: HasOnboardingConfig) -> None:
        """Run the onboarding-protocol policy check against the active security config."""
        from management.models import SecurityConfig  # noqa: PLC0415

        try:
            cfg: SecurityConfig = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            self.logger.warning(
                'OnboardingProtocolAuthorization: no SecurityConfig found; skipping check.'
            )
            return
        except SecurityConfig.MultipleObjectsReturned:
            cfg = SecurityConfig.objects.first()  # type: ignore[assignment]
            self.logger.warning(
                'OnboardingProtocolAuthorization: multiple SecurityConfig rows found; using first.'
            )

        self._strategy.check(subject, cfg)


class NoOnboardingPkiProtocolAuthorization(LoggerMixin):
    """Checks that the already-onboarded subject's active PKI protocols are permitted by the security config."""

    def __init__(self, strategy: ProtocolCheckStrategy | None = None) -> None:
        """Initialize with an optional custom strategy."""
        self._strategy: ProtocolCheckStrategy = strategy or _NoOnboardingPkiProtocolStrategy()

    def check(self, subject: HasOnboardingConfig) -> None:
        """Run the no-onboarding PKI-protocol policy check against the active security config."""
        from management.models import SecurityConfig  # noqa: PLC0415

        try:
            cfg: SecurityConfig = SecurityConfig.objects.get()
        except SecurityConfig.DoesNotExist:
            self.logger.warning(
                'NoOnboardingPkiProtocolAuthorization: no SecurityConfig found; skipping check.'
            )
            return
        except SecurityConfig.MultipleObjectsReturned:
            cfg = SecurityConfig.objects.first()  # type: ignore[assignment]
            self.logger.warning(
                'NoOnboardingPkiProtocolAuthorization: multiple SecurityConfig rows found; using first.'
            )

        self._strategy.check(subject, cfg)


class PermittedProtocolsAuthorization(LoggerMixin):
    """Dispatcher that selects the correct protocol authorization check based on the subject's state."""

    def __init__(
        self,
        onboarding_strategy: ProtocolCheckStrategy | None = None,
        no_onboarding_strategy: ProtocolCheckStrategy | None = None,
    ) -> None:
        """Initialize with optional custom strategies for each path."""
        self._onboarding_auth = OnboardingProtocolAuthorization(onboarding_strategy)
        self._no_onboarding_auth = NoOnboardingPkiProtocolAuthorization(no_onboarding_strategy)

    def check(self, subject: HasOnboardingConfig) -> None:
        """Dispatch to the correct authorization check for *subject*."""
        if getattr(subject, 'onboarding_config', None) is not None:
            self.logger.debug(
                'PermittedProtocolsAuthorization: dispatching to OnboardingProtocolAuthorization for %s.',
                subject,
            )
            self._onboarding_auth.check(subject)
        elif getattr(subject, 'no_onboarding_config', None) is not None:
            self.logger.debug(
                'PermittedProtocolsAuthorization: dispatching to NoOnboardingPkiProtocolAuthorization for %s.',
                subject,
            )
            self._no_onboarding_auth.check(subject)
        else:
            self.logger.debug(
                'PermittedProtocolsAuthorization: %s has neither onboarding_config '
                'nor no_onboarding_config; skipping.',
                subject,
            )
