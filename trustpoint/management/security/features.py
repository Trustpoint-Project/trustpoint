"""Management app feature."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, cast

from pki.auto_gen_pki import AutoGenPki
from trustpoint.logger import LoggerMixin

from management.models import SecurityConfig

if TYPE_CHECKING:
    from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityFeature(ABC):
    """Abstract base class for a security feature."""

    verbose_name: str | None = None
    db_field_name: str | None = None

    @abstractmethod
    def enable(self, **kwargs: object) -> None:
        """Enables the feature."""

    @abstractmethod
    def disable(self, **kwargs: object) -> None:
        """Disables the feature."""

    @abstractmethod
    def is_enabled(self) -> bool:
        """Returns True if the feature is currently enabled."""


class AutoGenPkiFeature(SecurityFeature, LoggerMixin):
    """Manages the auto-generated local CAs (PKI)."""

    verbose_name = 'Local Auto-Generated PKI'
    db_field_name = 'auto_gen_pki'

    @classmethod
    def is_enabled(cls) -> bool:
        """Returns True if the auto-generated PKI is enabled."""
        config = SecurityConfig.objects.first()
        return config.auto_gen_pki if config else False

    @classmethod
    def enable(cls, **kwargs: object) -> None:
        """Starts a thread that enables the auto-generated PKI."""
        cls.logger.info('AutoGenPkiFeature.enable() called with kwargs: %s', kwargs)
        cls.logger.info('is_enabled() returns: %s', cls.is_enabled())
        if cls.is_enabled():
            key_alg = kwargs.get('key_algorithm')
            if key_alg is None:
                msg = 'key_algorithm is required to enable AutoGenPkiFeature'
                cls.logger.error(msg)
                raise ValueError(msg)

            key_alg = cast('AutoGenPkiKeyAlgorithm', key_alg)

            def _enable_with_error_handling() -> None:
                """Wrapper to catch exceptions in the enable thread."""
                try:
                    cls.logger.info('Starting enable auto-generated PKI in background thread with key_alg: %s', key_alg)
                    AutoGenPki.enable_auto_gen_pki(key_alg)
                    cls.logger.info('enable_auto_gen_pki() completed successfully')
                except Exception:
                    cls.logger.exception('Failed to enable auto-generated PKI in background thread')

            thread = threading.Thread(target=_enable_with_error_handling, name='AutoGenPKI-Enable')
            thread.start()
        else:
            cls.logger.warning('AutoGenPkiFeature.enable() called but is_enabled() returned False - not enabling')

    @classmethod
    def disable(cls, **_kwargs: object) -> None:
        """Starts a thread that disables the auto-generated PKI."""
        cls.logger.info('AutoGenPkiFeature.disable() called')

        def _disable_with_error_handling() -> None:
            """Wrapper to catch exceptions in the disable thread."""
            try:
                cls.logger.info('Starting disable auto-generated PKI in background thread')

                AutoGenPki.disable_auto_gen_pki()
                cls.logger.info('disable_auto_gen_pki() completed successfully')
            except Exception:
                cls.logger.exception('Failed to disable auto-generated PKI in background thread')

        thread = threading.Thread(target=_disable_with_error_handling, name='AutoGenPKI-Disable')
        thread.start()

        conf = SecurityConfig.objects.first()
        if conf:
            conf.auto_gen_pki = False
            conf.save()
            cls.logger.info('SecurityConfig.auto_gen_pki set to False')
        else:
            cls.logger.warning('No SecurityConfig instance found to update auto_gen_pki')
