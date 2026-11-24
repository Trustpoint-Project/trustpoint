# Copyright (c) 2025 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Management app feature."""

from __future__ import annotations

from abc import ABC, abstractmethod

from management.models import SecurityConfig
from pki.auto_gen_pki import AutoGenPki
from trustpoint.logger import LoggerMixin


class SecurityFeature(ABC):
    """Abstract base class for a security feature."""

    verbose_name: str | None = None
    db_field_name: str | None = None

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
    def disable(cls, **_kwargs: object) -> None:
        """Disable the auto-generated PKI and revoke its certificates synchronously."""
        cls.logger.info('AutoGenPkiFeature.disable() called')
        AutoGenPki.disable_auto_gen_pki()
        cls.logger.info('disable_auto_gen_pki() completed successfully')
