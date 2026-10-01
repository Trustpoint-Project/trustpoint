# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Request-scoped internationalization context."""

from contextvars import ContextVar
from typing import Any

_current_user: ContextVar[Any] = ContextVar('current_user', default=None)


def set_current_user(user: Any) -> Any:
    """Set the authenticated user for request-local date formatting."""
    return _current_user.set(user)


def reset_current_user(token: Any) -> None:
    """Restore the previous request-local user."""
    _current_user.reset(token)


def get_current_user() -> Any:
    """Return the request-local authenticated user, if one is active."""
    return _current_user.get()
