"""Mixin for enforcing security feature checks in Django views."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from settings.security.manager import SecurityManager

if TYPE_CHECKING:
    from settings.security.features import SecurityFeature


class SecurityLevelMixin:
    """A mixin that provides security feature checks for Django views."""

    def __init__(self, security_feature: type[SecurityFeature] | None = None, *args: Any, **kwargs: Any) -> None:
        """Initializes the SecurityLevelMixin with the specified security feature and redirect URL.

        Args:
            security_feature (SecurityFeature): The feature to check against the current security level.
            *args (Any): Additional positional arguments passed to the superclass.
            **kwargs (Any): Additional keyword arguments passed to the superclass.
        """
        super().__init__(*args, **kwargs)
        self.sec = SecurityManager()
        self.security_feature = security_feature

    def get_security_level(self) -> str:
        """Returns the security mode of the current security level instance.

        Returns:
            str: The security mode of the current security level instance.
        """
        return self.sec.get_security_level()
