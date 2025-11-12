"""Management app decorators."""
from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import TYPE_CHECKING, Any, TypeVar

from django.core.exceptions import PermissionDenied

from management.security.manager import SecurityManager

if TYPE_CHECKING:
    from management.security.features import SecurityFeature

F = TypeVar('F', bound=Callable[..., Any])


def security_level(feature: type[SecurityFeature] | SecurityFeature) -> Callable[[F], F]:
    """A decorator that checks whether a specific security feature is allowed based on the current security level.

    This decorator uses the SecurityManager to determine if the provided feature is permitted under the current
    security level. If the feature is not allowed, it raises a PermissionDenied exception.

    Args:
        feature: The feature class or instance to check against the current security level.

    Returns:
        The decorated function that will only execute if the feature is allowed.

    Raises:
        PermissionDenied: If the security level does not permit the requested feature.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            manager = SecurityManager()
            if not manager.is_feature_allowed(feature):
                msg = f'Security level does not allow access to feature: {feature}'
                raise PermissionDenied(msg)
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
