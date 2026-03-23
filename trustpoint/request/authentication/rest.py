"""Provides the 'RestAuthentication' class using the Composite pattern for modular REST authentication."""

from typing import Never

from devices.models import DeviceModel
from request.request_context import BaseRequestContext, RestBaseRequestContext
from trustpoint.logger import LoggerMixin

from .base import (
    AuthenticationComponent,
    ClientCertificateAuthentication,
    CompositeAuthentication,
    ReenrollmentAuthentication,
)


class RestUsernamePasswordAuthentication(AuthenticationComponent, LoggerMixin):
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
            device = DeviceModel.objects.select_related().filter(
                common_name=username
            ).first()

            if not device:
                self.logger.warning('REST authentication failed: Unknown username %s', username)
                self._raise_authentication_error()

            device_config = device.onboarding_config or device.no_onboarding_config

            if not isinstance(device, DeviceModel) or not device_config:
                self.logger.warning('REST authentication failed: Invalid device model for %s', username)
                self._raise_authentication_error()

            if not device_config.est_password:
                self.logger.warning('REST authentication failed: No password set for %s', username)
                self._raise_authentication_error()

            if password != device_config.est_password:
                self.logger.warning('REST authentication failed: Invalid password for %s', username)
                self._raise_authentication_error()

            self.logger.info('REST: Successfully authenticated device %s', username)
            context.device = device

        except ValueError:
            raise
        except Exception as e:
            self.logger.exception('REST authentication error for user %s', username)
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e

    def _raise_authentication_error(self) -> Never:
        """Raise authentication error with standardized message."""
        error_message = 'Authentication failed: Invalid username or password.'
        raise ValueError(error_message)


class RestAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for REST requests."""

    def __init__(self) -> None:
        """Initialize the REST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(RestUsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
