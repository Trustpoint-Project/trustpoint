"""Provides base authentication class using the Composite pattern for modular authentication."""

from abc import ABC, abstractmethod
from typing import Never

from devices.models import (
    DeviceModel,
    IssuedCredentialModel,
)
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from request.request_context import BaseRequestContext, HttpBaseRequestContext
from trustpoint.logger import LoggerMixin


class AuthenticationComponent(ABC):
    """Abstract base class for authentication components."""

    @abstractmethod
    def authenticate(self, context: BaseRequestContext) -> DeviceModel | None:
        """Authenticate a request using specific logic."""


class ClientCertificateAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via client certificates."""

    domain_credential_only: bool = True

    def __init__(self, *, domain_credential_only: bool = True) -> None:
        """Initialize the client certificate authentication component."""
        self.domain_credential_only = domain_credential_only

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if not context.client_certificate:
            return

        client_certificate = context.client_certificate

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)

            if self.domain_credential_only:
                is_valid, reason = issued_credential.is_valid_domain_credential()
            else:
                is_valid, reason = issued_credential.credential.is_valid_issued_credential()
            if not is_valid:
                self.logger.warning('Invalid client certificate: %s', reason)
                error_message = f'Invalid HTTP_SSL_CLIENT_CERT header: {reason}'
                self._raise_certificate_error(error_message)

            self.logger.info('Successfully authenticated device via client certificate')
            context.device = issued_credential.device

        except IssuedCredentialModel.DoesNotExist:
            self.logger.warning('Client certificate not found in issued credentials')
            error_message = 'Client certificate not recognized'
            self._raise_certificate_error(error_message)
        except ValueError:
            raise
        except Exception as e:
            self.logger.exception('Certificate authentication error')
            error_message = 'Certificate authentication failed'
            self._raise_certificate_error(error_message, e)

    def _raise_certificate_error(self, message: str, cause: Exception | None = None) -> Never:
        """Raise certificate authentication error with proper exception chaining."""
        if cause:
            raise ValueError(message) from cause
        raise ValueError(message)


class IDevIDAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        # Early return if raw_message is missing
        if not isinstance(context, HttpBaseRequestContext) or not context.raw_message:
            return

        try:
            # domain can be None, in that case IDevIDAuthenticator will infer it from registration pattern
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, context.domain)

            if device_or_none:
                self.logger.info('Successfully authenticated device via IDevID')
                context.device = device_or_none
                if not context.domain:
                    device_domain = context.device.domain
                    if not device_domain:
                        error_message = 'IDevID authentication failed: Device domain is not set.'
                        self.logger.warning('IDevID authentication failed: Device domain is not set')
                        self._raise_idevid_error(error_message)
                    context.domain = device_domain
                    context.domain_str = device_domain.unique_name
            else:
                error_message = 'IDevID authentication failed: No device associated.'
                self.logger.warning('IDevID authentication failed: No device associated')
                self._raise_idevid_error(error_message)

        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e}'
            self.logger.warning('Error validating the IDevID: %s', e)
            raise ValueError(error_message) from e
        except ValueError:
            raise
        except Exception as e:
            error_message = 'IDevID authentication failed due to unexpected error'
            self.logger.exception('Unexpected error during IDevID authentication')
            raise ValueError(error_message) from e

    def _raise_idevid_error(self, message: str) -> Never:
        """Raise IDevID authentication error."""
        raise ValueError(message)


class CompositeAuthentication(AuthenticationComponent, LoggerMixin):
    """Composite authenticator for grouping and executing multiple authentication methods."""

    def __init__(self) -> None:
        """Initialize the composite authenticator with a set of authentication components."""
        self.components: list[AuthenticationComponent] = []

    def add(self, component: AuthenticationComponent) -> None:
        """Add an authentication component to the composite."""
        self.components.append(component)

    def remove(self, component: AuthenticationComponent) -> None:
        """Remove an authentication component from the composite."""
        self.components.remove(component)

    def authenticate(self, context: BaseRequestContext) -> None:
        """Authenticate the request using all registered components."""
        authentication_errors = []

        self.logger.debug('Authentication components to try: %s',
                          [component.__class__.__name__ for component in self.components])
        for component in self.components:
            try:
                component.authenticate(context)
                if context.device is not None:
                    self.logger.info('Authentication successful using %s', component.__class__.__name__)
                    return
            except ValueError as e:
                authentication_errors.append(f'{component.__class__.__name__}: {e}')
                continue
            except Exception:
                self.logger.exception('Unexpected error in %s', component.__class__.__name__)
                authentication_errors.append(f'{component.__class__.__name__}: Unexpected error')
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        self.logger.warning('Authentication failed for all methods: %s', authentication_errors)
        context.http_response_content = 'Authentication failed.'
        context.http_response_status = 403
        raise ValueError(error_message)
