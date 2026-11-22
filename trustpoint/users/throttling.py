# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""DRF throttles that also work for agent requests.

Agent endpoints authenticate a ``TrustpointAgent`` object instead of a Django
user, so the stock throttles crash on ``request.user.is_authenticated``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from rest_framework.throttling import AnonRateThrottle, ScopedRateThrottle, UserRateThrottle

# Do not use time.time: tests (and some apps) replace that module attribute globally.
_timer = staticmethod(lambda: datetime.now(UTC).timestamp())


def _is_authenticated(user: Any) -> bool:
    return bool(getattr(user, 'is_authenticated', False))


class SafeAnonRateThrottle(AnonRateThrottle):
    """Anonymous throttle that tolerates a non-user principal."""

    timer = _timer

    def get_cache_key(self, request: Any, _view: Any) -> str | None:
        """Key anonymous requests by client address."""
        if _is_authenticated(getattr(request, 'user', None)):
            return None
        return self.cache_format % {'scope': self.scope, 'ident': self.get_ident(request)}


class SafeUserRateThrottle(UserRateThrottle):
    """Authenticated throttle that keys agents by their primary key."""

    timer = _timer

    def get_cache_key(self, request: Any, _view: Any) -> str | None:
        """Key authenticated principals, falling back to the client address."""
        user = getattr(request, 'user', None)
        ident = getattr(user, 'pk', None) if _is_authenticated(user) else None
        ident = ident or self.get_ident(request)
        return self.cache_format % {'scope': self.scope, 'ident': ident}


class SafeScopedRateThrottle(ScopedRateThrottle):
    """Scoped throttle that tolerates a non-user principal."""

    timer = _timer

    def get_cache_key(self, request: Any, view: Any) -> str | None:
        """Key the scoped bucket by principal or client address."""
        throttle_scope = getattr(view, 'throttle_scope', None)
        if not throttle_scope:
            return None
        user = getattr(request, 'user', None)
        ident = getattr(user, 'pk', None) if _is_authenticated(user) else None
        ident = ident or self.get_ident(request)
        return self.cache_format % {'scope': throttle_scope, 'ident': ident}
