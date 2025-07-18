"""Provides the `EstAuthentication` class using the Composite pattern for modular EST authentication."""

from abc import ABC, abstractmethod
from functools import lru_cache
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from devices.models import DeviceModel, IssuedCredentialModel
from pki.util.idevid import IDevIDAuthenticationError, IDevIDAuthenticator
from django.contrib.auth.hashers import check_password
from trustpoint.logger import LoggerMixin

from request.request_context import RequestContext

if TYPE_CHECKING:
    from pki.models import CredentialModel



class AuthenticationComponent(ABC):
    """Abstract base class for authentication components."""

    @abstractmethod
    def authenticate(self, context: RequestContext) -> DeviceModel | None:
        """Authenticate a request using specific logic."""


class UsernamePasswordAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via username/password credentials."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using username and password from the context."""
        if not (context.est_username and context.est_password):
            return None

        username = context.est_username
        password = context.est_password

        try:
            device = DeviceModel.objects.select_related().filter(
                common_name=username
            ).first()

            if not device:
                self.logger.warning(f"Authentication failed: Unknown username {username}")
                raise ValueError('Authentication failed: Invalid username or password.')

            print(check_password(password, device.est_password))
            print(password)
            print(device.est_password)

            # Use proper password hashing instead of plaintext comparison
            if password != device.est_password:
                self.logger.warning(f"Authentication failed: Invalid password for {username}")
                raise ValueError('Authentication failed: Invalid username or password.')

            self.logger.info(f"Successfully authenticated device {username}")
            context.device = device

        except Exception as e:
            self.logger.error(f"Authentication error for user {username}: {e}")
            error_message = 'Authentication failed: Invalid username or password.'
            raise ValueError(error_message) from e


class ClientCertificateAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via client certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate using the client certificate from the context."""
        if not context.client_certificate:
            return None

        client_certificate = context.client_certificate

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_certificate)

            is_valid, reason = issued_credential.is_valid_domain_credential()
            if not is_valid:
                self.logger.warning(f"Invalid client certificate: {reason}")
                error_message = f'Invalid SSL_CLIENT_CERT header: {reason}'
                raise ValueError(error_message)

            self.logger.info("Successfully authenticated device via client certificate")
            context.device = issued_credential.device

        except IssuedCredentialModel.DoesNotExist:
            self.logger.warning("Client certificate not found in issued credentials")
            error_message = 'Client certificate not recognized'
            raise ValueError(error_message) from None
        except ValueError:
            raise
        except Exception as e:
            self.logger.error(f"Certificate authentication error: {e}")
            error_message = 'Certificate authentication failed'
            raise ValueError(error_message) from e


class ReenrollmentAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication for EST reenrollment using an Application Credential."""

    def _validate_certificate_extensions(self, credential_cert, client_cert, csr):
        """Validate that certificate extensions match between credential, client cert, and CSR."""
        try:
            credential_cert_san = credential_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            credential_cert_san = None

        try:
            csr_san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            csr_san = None

        try:
            client_san = client_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except x509.ExtensionNotFound:
            client_san = None

        if client_san != csr_san or credential_cert_san != csr_san:
            error_message = 'CSR/client SAN does not match the credential certificate SAN.'
            raise ValueError(error_message)


    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the client for reenrollment."""
        client_cert = context.client_certificate
        if not client_cert:
            return None

        csr = context.cert_requested
        if not csr:
            error_message = 'CSR is missing in the context for reenrollment.'
            self.logger.warning(error_message)
            raise ValueError(error_message)

        try:
            issued_credential = IssuedCredentialModel.get_credential_for_certificate(client_cert)
        except IssuedCredentialModel.DoesNotExist:
            error_message = "Issued credential not found for client certificate during reenrollment"
            self.logger.warning(error_message)
            raise ValueError(error_message) from None

        credential_model: CredentialModel = issued_credential.credential

        is_valid, reason = credential_model.is_valid_issued_credential()
        if not is_valid:
            error_message = f"Invalid client certificate for reenrollment: {reason}"
            self.logger.warning(error_message)
            raise ValueError(error_message)

        # Verify that the client certificate and CSR subjects match the existing issued credential
        if (
            not credential_model.certificate.subjects_match(csr.subject) or
            not credential_model.certificate.subjects_match(client_cert.subject)
        ):
            error_message = "CSR/client subject does not match the credential certificate's subject"
            self.logger.warning(error_message)
            raise ValueError(error_message)

        try:
            credential_cert = credential_model.certificate.get_certificate_serializer().as_crypto()
            self._validate_certificate_extensions(credential_cert, client_cert, csr)
        except Exception as e:
            self.logger.warning(f"Certificate extension validation failed: {e}")
            error_message = 'Certificate extension validation failed'
            raise ValueError(error_message) from e

        self.logger.info("Successfully authenticated device for reenrollment")
        context.device = issued_credential.device


class IDevIDAuthentication(AuthenticationComponent, LoggerMixin):
    """Handles authentication via IDevID certificates."""

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using the IDevID mechanism."""
        # Early return if domain is missing
        if not context.domain:
            return None

        # Early return if raw_message is missing
        if not context.raw_message:
            return None

        try:
            device_or_none = IDevIDAuthenticator.authenticate_idevid(context.raw_message, context.domain)

            if device_or_none:
                self.logger.info("Successfully authenticated device via IDevID")
                context.device = device_or_none
            else:
                error_message = 'IDevID authentication failed: No device associated.'
                self.logger.warning("IDevID authentication failed: No device associated")
                raise ValueError(error_message)

        except IDevIDAuthenticationError as e:
            error_message = f'Error validating the IDevID: {e}'
            self.logger.warning(f'Error validating the IDevID: {e}')
            raise ValueError(error_message) from e
        except ValueError:
            raise
        except Exception as e:
            error_message = 'IDevID authentication failed due to unexpected error'
            self.logger.error(f"Unexpected error during IDevID authentication: {e}")
            raise ValueError(error_message) from e


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

    def authenticate(self, context: RequestContext) -> None:
        """Authenticate the request using all registered components."""
        authentication_errors = []

        for component in self.components:
            try:
                component.authenticate(context)
                if context.device is not None:
                    self.logger.info(f"Authentication successful using {component.__class__.__name__}")
                    return
            except ValueError as e:
                authentication_errors.append(f"{component.__class__.__name__}: {e}")
                continue
            except Exception as e:
                self.logger.error(f"Unexpected error in {component.__class__.__name__}: {e}")
                authentication_errors.append(f"{component.__class__.__name__}: Unexpected error")
                continue
        error_message = 'Authentication failed: All authentication methods were unsuccessful.'
        self.logger.warning(f"Authentication failed for all methods: {authentication_errors}")
        raise ValueError(error_message)

class EstAuthentication(CompositeAuthentication):
    """Composite authenticator specifically for EST requests, combining various authentication methods."""

    def __init__(self) -> None:
        """Initialize the EST authenticator with a set of authentication methods."""
        super().__init__()
        self.add(ReenrollmentAuthentication())
        self.add(UsernamePasswordAuthentication())
        self.add(ClientCertificateAuthentication())
        self.add(IDevIDAuthentication())
