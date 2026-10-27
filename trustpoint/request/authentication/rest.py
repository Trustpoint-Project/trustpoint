# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Provides the 'RestAuthentication' class using the Composite pattern for modular REST authentication."""


from request.request_context import BaseRequestContext, RestBaseRequestContext

from .base import (
    ClientCertificateAuthentication,
    CompositeAuthentication,
    DevicePasswordAuthentication,
    ReenrollmentAuthentication,
)


class RestUsernamePasswordAuthentication(DevicePasswordAuthentication):
    """Handles authentication via username/password credentials for REST requests."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using username and password from the context."""
        if not isinstance(context, RestBaseRequestContext):
            exc_msg = 'RestUsernamePasswordAuthentication requires a RestBaseRequestContext.'
            raise TypeError(exc_msg)

        if not (context.rest_username and context.rest_password):
            return

        username = context.rest_username
        password = context.rest_password

        try:
            self._authenticate_credentials(context, username, password)

        except ValueError:
            raise
        except Exception as e:
            self.logger.exception('REST authentication error for user %s', username)
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e


class RestAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for REST requests."""

    def __init__(self) -> None:
        """Initialize the REST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(RestUsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
