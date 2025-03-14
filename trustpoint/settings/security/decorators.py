"""Security decorator for enforcing security level restrictions."""
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, cast

from django.core.exceptions import PermissionDenied

from settings.security.features import SecurityFeature
from settings.security.manager import SecurityManager

F = TypeVar('F', bound=Callable[..., Any])

def security_level(feature_name: type[SecurityFeature]) -> Callable[[F], F]:
    """Checks if a security feature is allowed based on the current security level.

    This decorator ensures that a specific security feature is permitted under the
    current security level. It utilizes `SecurityManager` to validate the feature.
    If the feature is not allowed, it raises a `PermissionDenied` exception.

    Args:
        feature_name (SecurityFeature): The feature to check against the current security level.

    Returns:
        Callable: The wrapped function that will execute only if the feature is allowed.
    """

    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            security_manager = SecurityManager()
            if not security_manager.is_feature_allowed(feature_name):
                msg = f'Security level does not allow access to feature: {feature_name}'
                raise PermissionDenied(msg)
            return func(*args, **kwargs)

        return cast(F, wrapper)

    return decorator
