"""Defines security features and their management within TrustPoint."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pki.auto_gen_pki import AutoGenPki

from settings.models import SecurityConfig

if TYPE_CHECKING:
    from pki.util.keys import AutoGenPkiKeyAlgorithm


class SecurityFeature(ABC):
    """Abstract base class for a security feature."""

    verbose_name = ''
    db_field_name = ''

    @classmethod
    @abstractmethod
    def enable(cls, *_args: Any) -> None:
        """Enables the feature."""

    @classmethod
    @abstractmethod
    def disable(cls, *_args: Any) -> None:
        """Disables the feature."""

    @classmethod
    @abstractmethod
    def is_enabled(cls) -> bool:
        """Returns True if the feature is currently enabled."""


class AutoGenPkiFeature(SecurityFeature):
    """Manages the auto-generated local CAs (PKI)."""

    verbose_name = 'Local Auto-Generated PKI'
    db_field_name = 'auto_gen_pki'

    @staticmethod
    def is_enabled() -> bool:
        """Returns True if the auto-generated PKI is enabled."""
        conf = SecurityConfig.objects.first()
        return conf.auto_gen_pki if conf else False

    @staticmethod
    def enable(key_alg: AutoGenPkiKeyAlgorithm) -> None:
        """Starts a thread that enables the auto-generated PKI.Pass thread arguments as a tuple to avoid any issues."""
        if AutoGenPkiFeature.is_enabled():
            thread = threading.Thread(target=AutoGenPki.enable_auto_gen_pki, args=(key_alg,))
            thread.start()

    @staticmethod
    def disable() -> None:
        """Starts a thread that disables the auto-generated PKI."""
        thread = threading.Thread(target=AutoGenPki.disable_auto_gen_pki)
        thread.start()

        conf = SecurityConfig.objects.first()
        if conf:
            conf.auto_gen_pki = False
            conf.save()
        else:
            msg = 'Failed to disable AutoGenPki: SecurityConfig instance not found.'
            raise RuntimeError(msg)
