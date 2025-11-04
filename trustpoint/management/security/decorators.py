"""Management app decorators."""
from functools import wraps
from typing import Any

from django.core.exceptions import PermissionDenied

from management.security import SecurityFeature
from management.security.manager import SecurityManager


def security_level(feature_name: SecurityFeature):
    """A decorator that checks whether a specific security feature is allowed based on the current security level.

    This decorator uses the SecurityManager to determine if the provided feature is permitted under the current
    security level. If the feature is not allowed, it raises a PermissionDenied exception.

    Parameters:
    -----------
    feature_name : SecurityFeatures
        The feature to check against the current security level.

    Returns:
    --------
    function
        The wrapped function that will only execute if the feature is allowed.

    Raises:
    -------
    PermissionDenied
        If the security level does not permit the requested feature.
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any):
            if not SecurityManager.is_feature_allowed(feature_name):
                raise PermissionDenied('Security level does not allow access to feature: %s' % feature_name)
            return func(*args, **kwargs)

        return wrapper

    return decorator
